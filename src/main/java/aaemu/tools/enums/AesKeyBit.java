package aaemu.tools.enums;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

/**
 * @author Shannon
 */
@Getter
@RequiredArgsConstructor
public enum AesKeyBit {
    _128(128),
    _192(192),
    _256(256);

    private final int bit;
}
