/* @LICENSE(MUSLC_MIT) */

.set noreorder
.global dlsym
.type dlsym,@function
dlsym:
	lui $gp, %hi(_gp_disp)
	addiu $gp, %lo(_gp_disp)
	addu $gp, $gp, $25
	move $6, $ra
	lw $25, %call16(__dlsym)($gp)
	addiu $sp, $sp, -16
	jalr $25
	sw $ra, 12($sp)
	lw $ra, 12($sp)
	jr $ra
	addiu $sp, $sp, 16
