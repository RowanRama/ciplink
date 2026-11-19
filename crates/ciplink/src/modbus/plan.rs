//! The read planner: the spans of resolved tags into the fewest requests. Pure.

use super::address::Area;

/// What one target reads: a span of one area of one unit (count in registers or bits).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Span {
    pub unit: u8,
    pub area: Area,
    pub start: u16,
    pub count: u16,
    /// Registers (or bits) per element: a span longer than one request is split only between elements, as
    /// many devices refuse a read that starts or ends inside a 32- or 64-bit value.
    pub step: u16,
}

impl Span {
    /// The last register or bit, as u32 so a span ending at 65535 does not overflow.
    fn end(&self) -> u32 {
        u32::from(self.start) + u32::from(self.count.max(1)) - 1
    }
}

/// Request size limits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Limits {
    pub max_registers: u16,
    pub max_bits: u16,
    pub max_gap: u16,
}

impl Limits {
    fn of(&self, area: Area) -> u16 {
        if area.is_bits() {
            self.max_bits
        } else {
            self.max_registers
        }
    }
}

/// One request to send: a span of one area of one unit, and the targets (indexes into the spans) it serves.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Block {
    pub unit: u8,
    pub area: Area,
    pub start: u16,
    pub count: u16,
    pub targets: Vec<usize>,
}

impl Block {
    fn end(&self) -> u32 {
        u32::from(self.start) + u32::from(self.count) - 1
    }
}

/// Plans the reads of `spans` into blocks: per unit and area, sorted by start, joined while the gap is at most
/// `max_gap` and the block fits the area's limit; a span longer than the limit is several blocks of its own.
pub(crate) fn plan(spans: &[Span], limits: Limits) -> Vec<Block> {
    let mut order: Vec<usize> = (0..spans.len()).collect();
    order.sort_by_key(|&i| {
        let s = &spans[i];
        (s.unit, s.area, s.start, std::cmp::Reverse(s.end()))
    });
    let mut blocks: Vec<Block> = Vec::new();
    let mut open: Option<Block> = None;
    for i in order {
        let span = spans[i];
        let limit = u32::from(limits.of(span.area).max(1));
        if let Some(block) = open.as_mut() {
            let joins = block.unit == span.unit
                && block.area == span.area
                && u32::from(span.start) <= block.end() + 1 + u32::from(limits.max_gap)
                && span.end().max(block.end()) - u32::from(block.start) < limit;
            if joins {
                let end = span.end().max(block.end());
                // end - start < limit <= 2000
                block.count = (end - u32::from(block.start) + 1) as u16;
                block.targets.push(i);
                continue;
            }
            blocks.extend(open.take());
        }
        let count = u32::from(span.count.max(1));
        if count <= limit {
            open = Some(Block {
                unit: span.unit,
                area: span.area,
                start: span.start,
                count: span.count.max(1),
                targets: vec![i],
            });
            continue;
        }
        // longer than one request: consecutive blocks of whole elements, serving this target alone
        let step = u32::from(span.step.max(1));
        let per = if step <= limit {
            limit - limit % step
        } else {
            limit
        };
        let mut start = u32::from(span.start);
        while start <= span.end() {
            let n = per.min(span.end() - start + 1);
            blocks.push(Block {
                unit: span.unit,
                area: span.area,
                // start <= end <= 65535 and n <= limit
                start: start as u16,
                count: n as u16,
                targets: vec![i],
            });
            start += n;
        }
    }
    blocks.extend(open);
    blocks
}

#[cfg(test)]
mod tests {
    use super::*;

    const LIMITS: Limits = Limits {
        max_registers: 125,
        max_bits: 2000,
        max_gap: 8,
    };

    fn hr(start: u16, count: u16) -> Span {
        Span {
            unit: 1,
            area: Area::Holding,
            start,
            count,
            step: 1,
        }
    }

    fn shape(blocks: &[Block]) -> Vec<(u8, Area, u16, u16, Vec<usize>)> {
        blocks
            .iter()
            .map(|b| (b.unit, b.area, b.start, b.count, b.targets.clone()))
            .collect()
    }

    #[test]
    fn contiguous_tags_are_one_block() {
        let blocks = plan(&[hr(2, 2), hr(0, 2), hr(4, 1)], LIMITS);
        assert_eq!(shape(&blocks), [(1, Area::Holding, 0, 5, vec![1, 0, 2])]);
    }

    #[test]
    fn gap_at_max_gap_joins_and_one_more_splits() {
        // registers 1..=8 unrequested: a gap of 8
        assert_eq!(plan(&[hr(0, 1), hr(9, 1)], LIMITS).len(), 1);
        assert_eq!(plan(&[hr(0, 1), hr(10, 1)], LIMITS).len(), 2);
        let no_gap = Limits {
            max_gap: 0,
            ..LIMITS
        };
        assert_eq!(plan(&[hr(0, 1), hr(1, 1)], no_gap).len(), 1);
        assert_eq!(plan(&[hr(0, 1), hr(2, 1)], no_gap).len(), 2);
    }

    #[test]
    fn limit_splits_blocks() {
        let blocks = plan(&[hr(0, 100), hr(100, 25), hr(125, 1)], LIMITS);
        assert_eq!(
            shape(&blocks),
            [
                (1, Area::Holding, 0, 125, vec![0, 1]),
                (1, Area::Holding, 125, 1, vec![2])
            ]
        );
        let picky = Limits {
            max_registers: 10,
            ..LIMITS
        };
        assert_eq!(plan(&[hr(0, 2), hr(8, 2), hr(9, 2)], picky).len(), 2);
    }

    #[test]
    fn long_array_spans_several_blocks() {
        let blocks = plan(&[hr(10, 300), hr(0, 1)], LIMITS);
        assert_eq!(
            shape(&blocks),
            [
                (1, Area::Holding, 0, 1, vec![1]),
                (1, Area::Holding, 10, 125, vec![0]),
                (1, Area::Holding, 135, 125, vec![0]),
                (1, Area::Holding, 260, 50, vec![0]),
            ]
        );
        let coils = Span {
            unit: 1,
            area: Area::Coil,
            start: 0,
            count: 4500,
            step: 1,
        };
        let counts: Vec<u16> = plan(&[coils], LIMITS).iter().map(|b| b.count).collect();
        assert_eq!(counts, [2000, 2000, 500]);
        let end = hr(65400, 136);
        let blocks = plan(&[end], LIMITS);
        assert_eq!(blocks[1].start, 65525);
        assert_eq!(blocks[1].count, 11);
    }

    #[test]
    fn long_array_splits_between_elements() {
        // float32{100}: 124 registers (62 floats) per request, never half a float in each
        let floats = Span {
            step: 2,
            ..hr(0, 200)
        };
        assert_eq!(
            shape(&plan(&[floats], LIMITS)),
            [
                (1, Area::Holding, 0, 124, vec![0]),
                (1, Area::Holding, 124, 76, vec![0]),
            ]
        );
        let doubles = Span {
            step: 4,
            ..hr(0, 200)
        };
        let counts: Vec<u16> = plan(&[doubles], LIMITS).iter().map(|b| b.count).collect();
        assert_eq!(counts, [124, 76]);
        let picky = Limits {
            max_registers: 3,
            ..LIMITS
        };
        let counts: Vec<u16> = plan(&[doubles], picky).iter().map(|b| b.count).collect();
        assert!(
            counts.iter().all(|&n| n == 3 || n == 2),
            "a limit below one element: {counts:?}"
        );
    }

    #[test]
    fn units_and_areas_never_join() {
        let spans = [
            hr(0, 1),
            Span {
                unit: 2,
                ..hr(1, 1)
            },
            Span {
                area: Area::Input,
                ..hr(1, 1)
            },
            Span {
                area: Area::Coil,
                ..hr(0, 1)
            },
            Span {
                area: Area::Discrete,
                ..hr(0, 1)
            },
        ];
        let blocks = plan(&spans, LIMITS);
        let order: Vec<(u8, Area)> = blocks.iter().map(|b| (b.unit, b.area)).collect();
        assert_eq!(
            order,
            [
                (1, Area::Coil),
                (1, Area::Discrete),
                (1, Area::Holding),
                (1, Area::Input),
                (2, Area::Holding)
            ]
        );
    }

    #[test]
    fn duplicates_and_overlaps_share_a_block() {
        let blocks = plan(&[hr(0, 2), hr(0, 2), hr(1, 1), hr(0, 4)], LIMITS);
        assert_eq!(shape(&blocks), [(1, Area::Holding, 0, 4, vec![3, 0, 1, 2])]);
    }

    #[test]
    fn bit_and_word_share_a_register() {
        // a bit of register 5 and the uint16 at 5 both span register 5
        let blocks = plan(&[hr(5, 1), hr(5, 1)], LIMITS);
        assert_eq!(shape(&blocks), [(1, Area::Holding, 5, 1, vec![0, 1])]);
    }
}
