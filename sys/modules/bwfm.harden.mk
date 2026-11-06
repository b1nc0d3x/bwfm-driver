# Extra warnings and hardening for the bwfm modules.
# Include after bsd.kmod.mk so these flags come last.
# Kernel headers trip ignored-qualifiers, and sign-compare under INVARIANTS.

CWARNFLAGS+=	-Wextra -Wformat=2 -Wshadow -Wvla -Wnull-dereference \
		-Wno-unused-parameter -Wno-missing-field-initializers \
		-Wno-ignored-qualifiers -Wno-error=sign-compare

CFLAGS+=	-fstack-protector-strong \
		-fstack-clash-protection \
		-ftrivial-auto-var-init=zero \
		-fno-delete-null-pointer-checks
