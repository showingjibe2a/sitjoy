"""Quick win-check regression (run: python scripts/test_mj_win.py)."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.mahjong_play_mixin import MahjongPlayMixin


class _T(MahjongPlayMixin):
    pass


def room(hands, melds, preset='hangzhou'):
    return {
        'rule_preset': preset,
        'hands': hands,
        'melds': melds,
    }


def main():
    t = _T()
    seat = 0
    jokers = frozenset(['z7'])

    # 8 hand + 1 kong meld (old bug: 12 tiles combined -> False)
    hand8 = ['w4', 'w5', 'w6', 'p6', 's1', 's2', 's2', 'z7']
    melds1 = [[{'type': 'kong', 'tiles': ['w7'] * 4}]]
    r1 = room([hand8], melds1)
    assert t._mj_can_win_seat(r1, seat) is False  # need 11 in hand with 1 meld

    # 8 hand + 2 melds (kong + pung/chi)
    melds2 = [
        [
            {'type': 'kong', 'tiles': ['w7'] * 4},
            {'type': 'pung', 'tiles': ['p9'] * 3},
        ],
    ]
    r2 = room([hand8], melds2)
    assert t._mj_can_win_seat(r2, seat) is True, 'expected win with 2 melds + joker hand'

    # 14 hand no melds
    hand14 = ['w1', 'w2', 'w3', 'w4', 'w5', 'w6', 'p1', 'p1', 'p1', 's4', 's5', 's6', 'z2', 'z2']
    r3 = room([hand14], [[], [], [], []], preset='standard')
    assert t._mj_can_win_seat(r3, seat) is True

    # ron: 13 + 1
    hand13 = hand14[:-1]
    r4 = room([hand13], [[], [], [], []], preset='standard')
    assert t._mj_can_win_seat(r4, seat, extra_tile='z2') is True

    print('ok')


if __name__ == '__main__':
    main()
