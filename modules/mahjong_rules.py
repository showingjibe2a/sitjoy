"""麻将规则预设（大厅内由房主选定，开局后不可改）。"""

MJ_PRESET_STANDARD = 'standard'
MJ_PRESET_HANGZHOU = 'hangzhou'

MJ_PRESETS = {
    MJ_PRESET_STANDARD: {
        'id': MJ_PRESET_STANDARD,
        'label': '标准（当前）',
        'summary': '136 张；可点炮/自摸；仅平胡；庄闲双倍计分，无连庄加倍。',
        'allow_ron': True,
        'joker_tiles': (),
        'dealer_streak_scoring': False,
        'dealer_streak_on_draw': False,
        'dealer_streak_on_dealer_win': False,
    },
    MJ_PRESET_HANGZHOU: {
        'id': MJ_PRESET_HANGZHOU,
        'label': '杭麻',
        'summary': '白板财神；仅自摸；暴头/财飘/杠开等牌型加倍；连庄 2→4→8 倍。',
        'allow_ron': False,
        'joker_tiles': ('z7',),
        'dealer_streak_scoring': True,
        'dealer_streak_on_draw': True,
        'dealer_streak_on_dealer_win': True,
        'hz_special_patterns': True,
    },
}

MJ_HZ_PATTERN_LABELS = {
    'pinghu': '平胡',
    'baotou': '暴头',
    'caipiao': '财飘',
    'double_caipiao': '双财飘',
    'gangkai': '杠开',
    'gangbao': '杠暴',
    'gangpiao': '杠飘',
}


def mj_hz_pattern_multiplier(is_baotou, joker_disc_streak, after_kong_draw):
    """牌型倍数（再乘连庄庄闲倍率）。封顶 8 倍。"""
    m = 1
    if is_baotou:
        m = 2
        if int(joker_disc_streak or 0) >= 2:
            m = 8
        elif int(joker_disc_streak or 0) >= 1:
            m = 4
    if after_kong_draw:
        m = min(8, m * 2)
    return m


def mj_hz_pattern_code(is_baotou, joker_disc_streak, after_kong_draw):
    streak = int(joker_disc_streak or 0)
    if after_kong_draw:
        if is_baotou:
            if streak >= 1:
                return 'gangpiao'
            return 'gangbao'
        return 'gangkai'
    if is_baotou:
        if streak >= 2:
            return 'double_caipiao'
        if streak >= 1:
            return 'caipiao'
        return 'baotou'
    return 'pinghu'


def mj_hz_pattern_label(code):
    return MJ_HZ_PATTERN_LABELS.get(str(code or '').strip(), '平胡')


def mj_normalize_preset(raw):
    key = str(raw or MJ_PRESET_STANDARD).strip().lower()
    return key if key in MJ_PRESETS else MJ_PRESET_STANDARD


def mj_rules_for_preset(preset_id):
    return dict(MJ_PRESETS[mj_normalize_preset(preset_id)])


def mj_preset_public_list():
    return [
        {
            'id': p['id'],
            'label': p['label'],
            'summary': p['summary'],
        }
        for p in MJ_PRESETS.values()
    ]


def mj_dealer_streak_multiplier(streak, cap=8):
    """连庄次数 streak：0=新庄/一庄(2倍)，1=二连庄(4倍)，2+=三连庄(8倍封顶)。"""
    s = max(0, int(streak or 0))
    return min(int(cap), 2 * (2 ** s))
