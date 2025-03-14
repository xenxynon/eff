#!/usr/bin/env python3

from ctypes import Structure, c_char, c_double, c_uint32, sizeof
import hashlib
from io import BufferedReader
from itertools import combinations
import struct
import sys
from typing import Dict, List, TextIO, Tuple
from enum import Enum


SHA_SIZE = 0x14
MAX_SUPPORTED_VERSION = 5


class EffectId(int, Enum):
    CLICK = 0
    DOUBLE_CLICK = 1
    TICK = 2
    THUD = 3
    POP = 4
    HEAVY_CLICK = 5
    RINGTONE_1 = 6
    RINGTONE_2 = 7
    RINGTONE_3 = 8
    RINGTONE_4 = 9
    RINGTONE_5 = 10
    RINGTONE_6 = 11
    RINGTONE_7 = 12
    RINGTONE_8 = 13
    RINGTONE_9 = 14
    RINGTONE_10 = 15
    RINGTONE_11 = 16
    RINGTONE_12 = 17
    RINGTONE_13 = 18
    RINGTONE_14 = 19
    RINGTONE_15 = 20
    TEXTURE_TICK = 21

    def int_str(self):
        return int(self), self.name.lower()



class DecryptionUnit(Structure):
    _fields_ = [
        ("first", c_uint32),
        ("second", c_uint32),
    ]


class ConfigHeader(Structure):
    _fields_ = [
        ("version", c_uint32),
        ("size", c_uint32),
        ("unknown0", c_double),
        ("client", c_char * 20),
        ("client_item", c_char * 20),
        ("device_type", c_char * 20),
        ("vibrator_type", c_char * 20),
    ]


class ConfigParamsV1(Structure):
    _fields_ = [
        ("unknown0", c_double),
        ("unknown1", c_double),
        ("unknown2", c_double),
        ("unknown3", c_double),
        ("unknown4", c_double),
        ("unknown5", c_double),
        ("unknown6", c_double),
        ("unknown7", c_double),
        ("unknown8", c_double),
        ("unknown9", c_double),
        ("unknown10", c_double),
    ]


class ConfigParamsV2(Structure):
    _fields_ = [
        ("interrupt_protect_time", c_double),
    ]


class ConfigParamsV3(Structure):
    _fields_ = [
        ("unknown1", c_double),
    ]


class ConfigParamsV4(Structure):
    _fields_ = [
        ("jnd_value", c_double),
        ("jnd_step", c_double),
    ]


class ConfigMore(Structure):
    _fields_ = [
        ("unknown0", c_uint32),
        ("size", c_uint32),
        ("length", c_uint32),
        ("unknown1", c_uint32),
    ]


class ConfigEffectArrays(Structure):
    _fields_ = [
        ("unknown0", c_uint32),
        ("unknown1", c_uint32),
        ("length", c_uint32),
        ("unknown2", c_uint32),
    ]


class ConfigEffects(Structure):
    _fields_ = [
        ("unknown0", c_uint32),
        ("size", c_uint32),
        ("unknown1", c_uint32),
    ]


class ConfigEffect(Structure):
    _fields_ = [
        ("id", c_uint32),
        ("effect_level", c_uint32),
        ("size", c_uint32),
        ("unknown0", c_uint32),
    ]


class Effect:
    def __init__(self):
        self.effect_level_data: Dict[int, bytearray] = {}

    def add_effect(self, effect_level: int, effect_data: bytearray):
        self.effect_level_data[effect_level] = effect_data

    @property
    def name(self): ...


class PrebakedEffect(Effect):
    def __init__(self, group: int, effect_id: int):
        super().__init__()
        self.group = group
        self.effect_id = effect_id

    @property
    def name(self):
        return f"{self.group}_{self.effect_id}"


class ComposedEffect(Effect):
    def __init__(self, name: str):
        super().__init__()

        self.__name = name

    @property
    def name(self):
        return self.__name


effect_ids_map_type = Dict[EffectId, Tuple[int, int]]


def decrypt_data(data: bytes):
    CONST_1 = 0x7C66FDF2
    CONST_2 = 0x11FD7ED1
    CONST_3 = 0x2F64EEF7
    CONST_4 = 0x518FEEFE

    CONST_5 = -0xC881070
    CONST_5_ITERATIONS = 16

    CONST_6 = 0x60C88107
    CONST_7 = 0x10
    MASK = 0xFFFFFFFF

    offset = 0
    decrypted_data = bytearray()
    while offset < len(data):
        rolling_const_5 = CONST_5

        unit = DecryptionUnit.from_buffer_copy(data, offset)
        offset += sizeof(unit)

        first = unit.first
        second = unit.second

        for _ in range(CONST_5_ITERATIONS):
            second = second - (
                CONST_1 + first * CONST_7
                ^ first + rolling_const_5
                ^ CONST_2 + (first >> 5)
            )
            second &= MASK

            first = first - (
                CONST_3 + second * CONST_7
                ^ rolling_const_5 + second
                ^ CONST_4 + (second >> 5)
            )
            first &= MASK

            rolling_const_5 += CONST_6
            rolling_const_5 &= MASK

        decrypted_data += bytes(DecryptionUnit(first=first, second=second))

    return decrypted_data


def unpack_int8_t(value):
    bytes_value = value.to_bytes(1, byteorder="little")
    return struct.unpack("<b", bytes_value)[0]


def offsetof_class(cls, member):
    return getattr(cls, member).offset


def offsetof(st, member):
    return offsetof_class(st.__class__, member)


def print_fields_offsets(st, start_offset=0):
    print(st.__class__.__name__)
    s = ""
    for field in st._fields_:
        name = field[0]
        value = getattr(st, name)
        offset = start_offset + offsetof(st, name)

        s += f"field: {name}, "
        s += f"value: {value}, "
        s += f"offset: {hex(offset)}, "

        offset32 = offset / 4
        offset32_int = int(offset32)
        if offset32_int == offset32:
            s += f"offset32: {hex(offset32_int)}, "

        s += "\n"

    print(s)


def parse_data(f: BufferedReader):
    expected_sha1 = f.read(SHA_SIZE)

    data = f.read()
    assert len(data) % 0x1400 == 0

    m = hashlib.sha1()
    m.update(data)
    sha1 = m.digest()

    assert expected_sha1 == sha1

    return decrypt_data(data)


def parse_config_header(data: bytearray):
    offset = 0

    config_header = ConfigHeader.from_buffer(data, offset)
    if config_header.version > MAX_SUPPORTED_VERSION:
        raise ValueError(f"Invalid version {config_header.version}")

    print_fields_offsets(config_header, offset)

    return config_header


def parse_params(config_header: ConfigHeader, data: bytearray):
    offset = sizeof(config_header)

    config_params_v1 = ConfigParamsV1.from_buffer(data, offset)
    print_fields_offsets(config_params_v1, offset)
    offset += sizeof(config_params_v1)

    if config_header.version < 2:
        return

    config_params_v2 = ConfigParamsV2.from_buffer(data, offset)
    print_fields_offsets(config_params_v2, offset)
    offset += sizeof(config_params_v2)

    if config_header.version < 3:
        return

    config_params_v3 = ConfigParamsV3.from_buffer(data, offset)
    print_fields_offsets(config_params_v3, offset)
    offset += sizeof(config_params_v3)

    if config_header.version < 4:
        return

    config_params_v4 = ConfigParamsV4.from_buffer(data, offset)
    print_fields_offsets(config_params_v4, offset)
    offset += sizeof(config_params_v4)

    end = sizeof(config_header) + config_header.size
    if offset != end:
        print("Leftover config header data:")
        print(data[offset:end])
        print()


def parse_prebak_effect(
    data: bytearray,
    offset: int,
    group: int,
    effect_id: int,
    effects: List[PrebakedEffect],
):
    effect = PrebakedEffect(group, effect_id)

    for _ in range(3):
        config_effect = ConfigEffect.from_buffer(data, offset)
        print_fields_offsets(config_effect, offset)
        offset += sizeof(config_effect)

        if config_effect.id - 1 != effect_id:
            raise ValueError(f"Invalid effect id: {config_effect.id}")

        if config_effect.effect_level > 3 or config_effect.effect_level < 1:
            raise ValueError(f"Invalid effect level: {config_effect.effect_level}")

        effect_data = data[offset : offset + config_effect.size]
        offset += config_effect.size

        effect.add_effect(config_effect.effect_level - 1, effect_data)

    effects.append(effect)

    return offset


def parse_prebak_effects(data: bytearray, group: int, effects: List[PrebakedEffect]):
    offset = 0

    config_effects = ConfigEffects.from_buffer(data, offset)
    print_fields_offsets(config_effects, offset)
    offset += sizeof(config_effects)

    for i in range(config_effects.size):
        offset = parse_prebak_effect(data, offset, group, i, effects)

    return offset


def parse_more(
    data: bytearray,
    offset: int,
):
    config_more = ConfigMore.from_buffer(data, offset)
    print_fields_offsets(config_more, offset)
    offset += sizeof(config_more)

    # TODO: find what this data is, as it seems very random
    # src = data[offset : offset + config_more.size]
    offset += config_more.size

    return offset, config_more


def parse_effect_arrays(
    data: bytearray,
    offset: int,
):
    config_effect_arrays = ConfigEffectArrays.from_buffer(data, offset)
    print_fields_offsets(config_effect_arrays, offset)
    offset += sizeof(config_effect_arrays)

    return offset, config_effect_arrays


def parse_effects(
    config_header: ConfigHeader,
    data: bytearray,
    effects: List[PrebakedEffect],
):
    offset = sizeof(ConfigHeader) + config_header.size

    for _ in range(2):
        offset, _ = parse_more(data, offset)

    offset += parse_prebak_effects(data[offset:], 0, effects)
    offset += parse_prebak_effects(data[offset:], 1, effects)

    return offset


def parse_effects_v5(
    config_header: ConfigHeader,
    data: bytearray,
    effects: List[PrebakedEffect],
):
    offset = sizeof(ConfigHeader) + config_header.size

    for _ in range(4):
        # Last two seem optional, but they parse fine even if they're
        # zeroed
        offset, _ = parse_more(data, offset)

    group = 0
    for _ in range(2):
        offset, config_effect_arrays = parse_effect_arrays(data, offset)
        for _ in range(config_effect_arrays.length):
            offset += parse_prebak_effects(data[offset:], group, effects)
            group += 1

    return offset


def get_effect_level_str(effect_level):
    if effect_level == 2:
        effect_strength = "strong"
    elif effect_level == 1:
        effect_strength = "medium"
    else:
        effect_strength = "light"

    return effect_strength


def get_effect_name(effect: ConfigEffect):
    return f"{effect.id - 1}"


def get_effect_arr_name(effect_name: str, effect_level: int):
    effect_level_str = get_effect_level_str(effect_level)
    return f"effect_{effect_name}_{effect_level_str}"


def get_effect_data_time_ms(effect_data: bytearray):
    return round(len(effect_data) * 1000 / 24000, 3)


def convert_effect_data_int(effect_data: bytearray):
    return [unpack_int8_t(x) for x in effect_data]


def convert_effect_data(
    effect_data: bytearray,
):
    effect_data_int = convert_effect_data_int(effect_data)
    # TODO: find out if zeros break the streaming
    # effect_data_int = [1 if x == 0 else x for x in effect_data_int]

    effect_data_strs = [str(x) for x in effect_data_int]
    # Pad left to align all of them
    effect_data_strs = [f"{x:>4}," for x in effect_data_strs]
    # Add one for space
    return effect_data_strs


def write_prebak_effect(
    o: TextIO,
    name: str,
    effect_level: int,
    effect_data: bytearray,
):
    effect_data_strs = convert_effect_data(effect_data)
    # Add one for space
    len_one_data = len(effect_data_strs[0]) + 1
    num_data_per_line = 80 // len_one_data

    effect_arr_name = get_effect_arr_name(name, effect_level)
    o.write(f"static const int8_t {effect_arr_name}[] = {{\n")
    for i, x in enumerate(effect_data_strs):
        o.write(x)

        if i != len(effect_data) - 1:
            if (i + 1) % num_data_per_line == 0:
                o.write("\n")
            else:
                o.write(" ")

    o.write("\n};\n")


def write_prebak_effects_array(
    o: TextIO,
    aosp_effect_id: EffectId,
    effect: Effect,
    effects_hz: int,
):
    effect_id_int, effect_id_str = aosp_effect_id.int_str()
    config_effect_data = effect.effect_level_data.items()
    sorted_pairs = sorted(config_effect_data)

    o.write(f"static const struct effect_stream effects_{effect_id_str}[] = {{\n")
    for effect_level, effect_data in sorted_pairs:
        effect_arr_name = get_effect_arr_name(effect.name, effect_level)

        o.write(
            f"""
    {{
        .effect_id = {effect_id_int},
        .length = {len(effect_data)},
        .play_rate_hz = {effects_hz},
        .data = {effect_arr_name},
    }},
""".lstrip("\n")
        )
    o.write("};\n\n")


def parse_config(config_path: str, effects: List[PrebakedEffect]):
    with open(config_path, "rb") as i:
        data = parse_data(i)

        config_header = parse_config_header(data)

        parse_params(config_header, data)
        if config_header.version == 5:
            offset = parse_effects_v5(config_header, data, effects)
        else:
            offset = parse_effects(config_header, data, effects)

        for byte in data[offset:]:
            assert byte == 0xFF or byte == 0x00


def get_effect_by_id(effects: List[PrebakedEffect], i: Tuple[int, int]):
    for effect in effects:
        if i[0] == effect.group and i[1] == effect.effect_id:
            return effect

    raise ValueError(f"Failed to find effect for id {i}")


def write_prebak_effects(o: TextIO, effect: Effect):
    for effect_level, effect_data in effect.effect_level_data.items():
        write_prebak_effect(o, effect.name, effect_level, effect_data)
        o.write("\n")


def write_effects(
    effects_path: str,
    effects: List[PrebakedEffect],
    effect_ids_map: effect_ids_map_type,
    effects_hz: int,
):
    with open(effects_path, "w", encoding="utf-8") as o:
        o.write(
            """
/*
 * SPDX-FileCopyrightText: 2025 The LineageOS Project
 * SPDX-License-Identifier: Apache-2.0
 */

""".lstrip()
        )

        for effect_ids in set(effect_ids_map.values()):
            effect = get_effect_by_id(effects, effect_ids)
            write_prebak_effects(o, effect)

        for aosp_effect_id, effect_ids in effect_ids_map.items():
            effect = get_effect_by_id(effects, effect_ids)

            write_prebak_effects_array(o, aosp_effect_id, effect, effects_hz)

        o.write("static const struct effect_stream *effects[] = {\n")
        for aosp_effect_id in sorted(effect_ids_map):
            effect_id_int, effect_id_str = aosp_effect_id.int_str()
            o.write(f"    [{effect_id_int}] = effects_{effect_id_str},\n")
        o.write("};\n")


def replace_in_aosp_effect_ids(
    effect_ids_map: effect_ids_map_type,
    removed: PrebakedEffect,
    replacement: PrebakedEffect,
):
    for aosp_effect_id, effect_ids in effect_ids_map.items():
        if (removed.group, removed.effect_id) == effect_ids:
            effect_ids_map[aosp_effect_id] = (replacement.group, replacement.effect_id)


def remove_duplicate_effects(
    effects: List[PrebakedEffect],
    effect_ids_map: effect_ids_map_type,
):
    # Remove duplicate effects
    removed_effects: List[PrebakedEffect] = []
    for first, second in combinations(effects, 2):
        all_effect_same = True

        for level, first_data in first.effect_level_data.items():
            second_data = second.effect_level_data[level]
            if first_data != second_data:
                all_effect_same = False

        if all_effect_same and second not in removed_effects:
            print(f"Remove effect {second.name}, duplicate of {first.name}")
            replace_in_aosp_effect_ids(effect_ids_map, second, first)
            removed_effects.append(second)

    for effect in removed_effects:
        effects.remove(effect)


def run():
    if len(sys.argv) < 2:
        raise ValueError(f"usage: {sys.argv[0]} <aac_richtap.config> [effects.cpp]")

    config_path = sys.argv[1]
    effects_path = None
    if len(sys.argv) == 3:
        effects_path = sys.argv[2]

    # Keys are AOSP Effect IDs
    # Values found by grepping logcat for `AacRichTapConvert: effect_id:`
    # and pressing buttons in VibeTest
    # By checking the data lengths, have found that the IDs are offset by
    # 0x3001
    # Leftover: (1, 0), (1, 1)
    effect_ids_map = {
        EffectId.CLICK: (1, 8),  # original: (1, 9), # with 0x3001: 12298
        EffectId.DOUBLE_CLICK: (0, 1),
        EffectId.TICK: (0, 0),  # deduped: (1, 1),  # original: (1, 2), # with 0x3001: 12291
        EffectId.THUD: (1, 6),  # with 0x3001: 12295
        EffectId.POP: (1, 7),  # with 0x3001: 12296
        EffectId.HEAVY_CLICK: (1, 5),  # original: (1, 6),  # with 0x3001: 12295
        EffectId.TEXTURE_TICK: (0, 2),  # no original
        # Use ringtones to test effects
        EffectId.RINGTONE_1: (0, 0),
        EffectId.RINGTONE_2: (0, 1),
        EffectId.RINGTONE_3: (0, 2),
        EffectId.RINGTONE_4: (1, 0),
        EffectId.RINGTONE_5: (1, 1),
        EffectId.RINGTONE_6: (1, 5),
        EffectId.RINGTONE_7: (1, 6),
        EffectId.RINGTONE_8: (1, 7),
        EffectId.RINGTONE_9: (1, 8),
    }
    effects_hz = 24000

    effects: List[PrebakedEffect] = []
    parse_config(config_path, effects)

    max_len = 0
    for effect in effects:
        for effect_data in effect.effect_level_data.values():
            max_len = max(max_len, len(effect_data))

    remove_duplicate_effects(effects, effect_ids_map)

    import matplotlib.pyplot as plt

    fig, axs = plt.subplots(len(effects), 3, figsize=(15, 15))
    for effect_index, effect in enumerate(effects):
        for effect_level, effect_data in effect.effect_level_data.items():
            converted_effect_data = convert_effect_data_int(effect_data)
            time_ms = get_effect_data_time_ms(effect_data)
            label = f"[{effect_index}] = {effect.name}@{effect_level} {time_ms}ms {len(effect_data)}samples"

            ax = axs[effect_index, effect_level]
            ax.set_ylim(-128, 127)
            ax.set_xlim(0, max_len)
            ax.plot(converted_effect_data)
            ax.set_title(label)

    plt.tight_layout()
    plt.show()

    if effects_path is not None:
        write_effects(effects_path, effects, effect_ids_map, effects_hz)


if __name__ == "__main__":
    run()
