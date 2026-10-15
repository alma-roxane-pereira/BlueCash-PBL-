package com.bluecash.wallet.ui.theme

import androidx.compose.ui.graphics.Color

/**
 * The BlueCash palette: deep indigo on near-white, in the manner of the banking
 * apps this is meant to feel like.
 *
 * Previously only three roles were defined, so `surface`, `background` and
 * everything built on them fell back to Material 3's baseline — which is
 * purple-tinted grey. Turning off dynamic colour exposed that rather than
 * fixing it. These are the full set, so no role is left to the default.
 */

// --- brand ------------------------------------------------------------------
/** The primary indigo: buttons, the selected tab, anything that acts. */
val Indigo = Color(0xFF2E2D88)
val IndigoDark = Color(0xFF1F1E63)
val IndigoLight = Color(0xFF4A47B8)

/** The two ends of the balance card's gradient. */
val GradientStart = Color(0xFF4A3FBF)
val GradientEnd = Color(0xFF7B6FE0)

/** For the small amount of warmth the layout needs — chips, highlights. */
val Amber = Color(0xFFF5A623)

// --- light ------------------------------------------------------------------
/** The page behind the cards. Grey, not white, so white cards read as raised. */
val PageGrey = Color(0xFFF1F2F6)
val CardWhite = Color(0xFFFFFFFF)
/** A second surface for rows inside a card. */
val RowGrey = Color(0xFFF7F8FB)
val InkDark = Color(0xFF16162E)
val InkMuted = Color(0xFF6E6E8A)
val HairlineLight = Color(0xFFE2E4EC)
/** A pale indigo wash, for selected chips and the active tab's pill. */
val IndigoTint = Color(0xFFE8E7F7)

// --- dark -------------------------------------------------------------------
// Not the light palette inverted: the indigo is lightened so it still reads as
// the brand against a dark page, and the greys are warmed slightly to avoid the
// blue cast that pure neutrals take on next to indigo.
val PageDark = Color(0xFF101018)
val CardDark = Color(0xFF1B1B26)
val RowDark = Color(0xFF23232F)
val InkLight = Color(0xFFECECF2)
val InkMutedDark = Color(0xFF9B9BB0)
val HairlineDark = Color(0xFF2E2E3C)
val IndigoOnDark = Color(0xFF9B93F0)
/** The dark-theme counterpart of [IndigoTint]. */
val IndigoTintDark = Color(0xFF2B2A4D)

// --- status -----------------------------------------------------------------
// A payment outcome is the one place colour carries meaning rather than style,
// so these are defined for both themes instead of being literals in the UI.
val SuccessLight = Color(0xFFDFF3E3)
val SuccessDark = Color(0xFF17351F)
val WarningLight = Color(0xFFFFF1CC)
val WarningDark = Color(0xFF3A2F11)
val ErrorLight = Color(0xFFFBE1DE)
val ErrorDark = Color(0xFF3C1D1B)
val NeutralLight = Color(0xFFEDEDED)
val NeutralDark = Color(0xFF26262F)
/** Material's error reds, named here so no role falls back to the default. */
val ErrorRed = Color(0xFFB3261E)
val ErrorRedOnDark = Color(0xFFF2B8B5)
