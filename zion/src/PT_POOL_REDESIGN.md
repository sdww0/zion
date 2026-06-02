# Zion SM 共享 PT Pool 重构方案

## 当前问题

PT pool 静态分区：每个 enclave 固定 2MB 子池 (512 个 4KB 页)。
大部分 enclave 页表远小于 2MB，浪费严重。增大 MAX_ENCLAVES 线性增加 PT 开销。

## 对齐约束

- SV48x4 G-stage 根页表: 16KB (4 页)，因为根级 index bits = 9+2 = 11，2048 × 8B = 16KB
- hgatp.PPN = root_pt >> PAGE_SHIFT，要求根页表 16KB 对齐
- 中间页表页 (L1/L2/L3): 4KB 对齐即可，无特殊要求
- PT pool 整体 2MB 对齐 → 每 16KB 边界天然 16KB 对齐

## 新设计

### 内存布局

```
PT Pool (共享，2MB 对齐):
┌──────────────────────────────────────────────┐
│  根页表区 (N × 16KB，固定槽位)                │
│  ┌────────┐ ┌────────┐ ┌────────┐ ┌────────┐│
│  │enc0    │ │enc1    │ │(空闲)  │ │(空闲)  ││
│  │root PT │ │root PT │ │        │ │        ││
│  │16KB    │ │16KB    │ │16KB    │ │16KB    ││
│  └────────┘ └────────┘ └────────┘ └────────┘│
├──────────────────────────────────────────────┤
│  中间页表区 (4KB 按需分配，全局共享)           │
│  ┌──┬──┬──┬──┬──┬──┬──┬──┬──┬──┬──┬──┬──┬──┐│
│  │  │  │  │  │  │  │  │  │  │  │  │  │  │  ││
│  └──┴──┴──┴──┴──┴──┴──┴──┴──┴──┴──┴──┴──┴──┘│
└──────────────────────────────────────────────┘
```

### 数据结构

```c
/* 根页表槽位 */
typedef struct {
    uint8_t *base;        // 16KB 对齐地址
    uint32_t owner_id;    // enclave id 或 -1 (空闲)
    bool     in_use;
} root_pt_slot_t;

/* 共享 PT pool */
typedef struct {
    uint8_t *base;
    size_t   total_size;

    /* 根页表区 */
    root_pt_slot_t root_slots[MAX_ENCLAVES];
    int            root_slot_count;

    /* 中间页表区 */
    uint8_t *mid_base;    // 中间页区起始
    size_t   mid_size;    // 中间页区大小
    size_t   mid_offset;  // 当前分配偏移 (4KB 单位)
} pt_pool_shared_t;
```

### 分配逻辑

1. **根页表分配** (create_enclave 时):
   - 从 root_slots[] 找空闲槽位
   - 返回槽位的 base (天然 16KB 对齐)
   - 标记 owner_id

2. **中间页分配** (map_gpa_to_hpa → get_pte_entry 时):
   - 从 mid_base + mid_offset 分配 4KB 页
   - mid_offset += 4KB
   - 无对齐要求

3. **释放** (destroy_enclave 时):
   - 清零根页表槽位 (16KB memset)
   - 标记槽位空闲
   - 中间页: 无法单独释放 (偏移式分配)
     - 方案A: 不释放，直到 pool reset
     - 方案B: per-enclave 中间页链表，逐个释放
     - 方案C: bump allocator + periodic compact (复杂)

### 需要修改的文件

| 文件 | 函数 | 改动 |
|------|------|------|
| tee-mem.h | pt_pool_t | 新增 pt_pool_shared_t 替换 |
| tee-mem.c | init_pt_pool() | 初始化共享池 |
| tee-mem.c | alloc_pt_page_enclave() | 从共享中间页区分配 |
| tee-mem.c | get_enclave_root_pt() | 从 root_slot 查找 |
| tee-mem.c | reset_enclave_pt_pool() | 释放根槽位 + 清零 |
| zion.h | MAX_ENCLAVES | 改为 16 |

### MAX_ENCLAVES=16 时的内存计算

```
总 TEE 内存: 128MB

根页表区: 16 × 16KB = 256KB (对齐到 2MB = 2MB)
中间页表区: 从 2MB 处开始
数据块池: 128MB - 2MB = 126MB → 63 个 2MB 块

对比当前:
  根页表区: 4 × 2MB = 8MB
  数据块池: 128MB - 8MB = 120MB → 60 个 2MB 块
```

节省 6MB，且支持 16 个 enclave 而非 4 个。

### 风险

- 中间页 bump allocator 不支持单个 enclave 释放
  → enclave 销毁频繁时会耗尽中间页区
  → 缓解: 中间页区给大一些 (比如 4-8MB)
  → 后续可改为 freelist 方案
