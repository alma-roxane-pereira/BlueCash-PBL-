package com.bluecash.wallet.ui.theme

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Shapes
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.unit.dp

/**
 * Every colour role is set explicitly.
 *
 * Material fills in anything left out from its baseline palette, which is
 * purple-tinted grey — that is why the app looked like a default template even
 * after dynamic colour was switched off. Naming all of them is the difference
 * between "the buttons are our blue" and "the app is ours".
 *
 * Dynamic colour stays off deliberately. A wallet should look the same on
 * every phone, because people recognise a payment app by its appearance, and
 * wallpaper-derived colours would make it different on each device.
 */

private val LightColors = lightColorScheme(
    primary = Indigo,
    onPrimary = CardWhite,
    primaryContainer = IndigoLight,
    onPrimaryContainer = CardWhite,

    secondary = IndigoLight,
    onSecondary = CardWhite,
    secondaryContainer = IndigoTint,
    onSecondaryContainer = IndigoDark,

    tertiary = Amber,
    onTertiary = InkDark,

    background = PageGrey,
    onBackground = InkDark,

    surface = CardWhite,
    onSurface = InkDark,
    surfaceVariant = RowGrey,
    onSurfaceVariant = InkMuted,

    outline = HairlineLight,
    outlineVariant = HairlineLight,

    error = ErrorRed,
    onError = CardWhite,
    errorContainer = ErrorLight,
    onErrorContainer = InkDark,
)

private val DarkColors = darkColorScheme(
    primary = IndigoOnDark,
    onPrimary = IndigoDark,
    primaryContainer = IndigoDark,
    onPrimaryContainer = InkLight,

    secondary = IndigoOnDark,
    onSecondary = IndigoDark,
    secondaryContainer = IndigoTintDark,
    onSecondaryContainer = InkLight,

    tertiary = Amber,
    onTertiary = InkDark,

    background = PageDark,
    onBackground = InkLight,

    surface = CardDark,
    onSurface = InkLight,
    surfaceVariant = RowDark,
    onSurfaceVariant = InkMutedDark,

    outline = HairlineDark,
    outlineVariant = HairlineDark,

    error = ErrorRedOnDark,
    onError = InkDark,
    errorContainer = ErrorDark,
    onErrorContainer = InkLight,
)

/**
 * Generous corners throughout. The reference this follows uses soft, card-like
 * shapes, and a payment card with sharp corners reads as a form, not money.
 */
private val BlueCashShapes = Shapes(
    extraSmall = RoundedCornerShape(8.dp),
    small = RoundedCornerShape(12.dp),
    medium = RoundedCornerShape(16.dp),
    large = RoundedCornerShape(20.dp),
    extraLarge = RoundedCornerShape(28.dp),
)

@Composable
fun BlueCashTheme(
    darkTheme: Boolean = isSystemInDarkTheme(),
    content: @Composable () -> Unit,
) {
    MaterialTheme(
        colorScheme = if (darkTheme) DarkColors else LightColors,
        typography = BlueCashTypography,
        shapes = BlueCashShapes,
        content = content,
    )
}
