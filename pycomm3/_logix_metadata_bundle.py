"""Generated sealed metadata credentials; reversible local obfuscation."""
import base64
from ._logix_bundle_codec import open_credentials

_BLOCKS = (
    'uaqeVqRwHD{(Pv`t8{p18+Ns)I{x!*bl9t_JYMB(J!4Db0yCX9w$~#rtGCaOc2D}LS6-Hc7JA5V?MTy3',
    'WnlPK!dQ?a@Lc%_Q;;?D#yWb7(`_cz(0LHa`wOD}pi47y(bjL~qRPX{gQ<Sla`V;ESNVb4T5tP+A8@pD',
    'Zh={^oB%8nb}HGn`Z%`(^hH6*uykD3k7(393&gMx31A4n7Qt}@rTA6_!3;n&aIB`{lWwua3*XPgFH;w&',
    'lD4?s!V{j7V1L|*^o~*M6#(+<=&Ww#I5s5{NSDR)?X+Znb`R~H_1@KqmImMr_AtDMGW+?C-ul94W0k=W',
    'HhqnsTL5Ja3Pc()RgO6DnjkPVw)}}L*3TsWcqWsJR$`i(Z+}e9rE2HR_Q(i`XnRDLuz=qTAVw&N`+tFG',
    '#{rU1Xzt#6VS+T&(8haBVoad{NOiGf>6UVQuOw|&j=<i54tpAH57erNlot80>4Slr<uvK*1RyOA)$L?<',
    'ppCpehcU8oE&z?NdliNMd_5(`G!;YVXZk+aZ3z|sXy_XW+X4qs(HmXV{Czf|LDY|;jrbXOp-GY',
    'RfWq&wx%QCsGonx{zGhJ>>PaY<ZgK*_)Iy<H{c`fTQFK^v>1>DNA^$kD|){Y><yCaqqXWQ>-%Xu6jFPq',
    'W|3nui(P|@bfl|YBwmy@;A*~D$!&}Wr|Q1Fcr`R*RG}`zlC{XiecE%qV9lnrz+bfb+9rOM#Y%Kk$Pt`A',
    '1}WV_H_Qr4rsq;qLO&EWm-IxBx*PciRnkQhOM>QGqo{`qL>8N9H*?zLx=uaXBXyMv6U;CEw_oa{;0noX',
    '5QHE~fIbVVJbZ#o56uf0ukhyxvBs{GAa0}aCqyvAY5?C!_sxPb*Tjj`IK(HV%_f~3MCLSmxK24cZ@NTV',
    'Wk_(8D6U8VB)2zqk}Sw`hicb|#;4(F(T_lF)IRGqI^oW<D@|Ce0D1yf&X3eW&#31(HClM$Q)ymS*RnDv',
    'Bi3)|iETOD-{H%c8WLbOGDNG~!Jr^u^FC<Jj=V-5h;|B`x`T|#Bn-`WlhR=mu=&x9Z)TbN+w+8md!Htd',
    'OifEM@QpPieJZHH*^_REvjG(hz}K9sgdV~ul{*}28zy{m0ujl$zE@%>pB{)|Wt^D_*nBT~i+?QqI9^%(',
    'eRw^ruoMDOPHs4&x{(B3q_!|Xbdzkz@B$BS<0Ppb<2)vvi*NW7K#_=hn38NBmU$a_jx$0kYzYV{*D&<V',
)
_ORDER = (13, 5, 9, 11, 12, 8, 1, 14, 3, 4, 7, 2, 10, 0, 6)
_MATERIAL = ('E-Lv+FnW<bcnV%ny0NhTiye<vXOaO{FaR@DzcZc!', 'CYm@FlgeeOr&|F6RJY7%=n@^Y{z4%`lAmSv`RY+j', 'hzSY`vL^W4+xT?7LCM>9jZcVavq)T>l%~;w<BX@j')


def load():
    data = base64.b85decode("".join(_BLOCKS[index] for index in _ORDER))
    parts = [base64.b85decode(value) for value in _MATERIAL]
    if len(parts) != 3 or any(len(part) != 32 for part in parts):
        raise ValueError("Invalid bundled credential material")
    material = bytes(a ^ b ^ c for a, b, c in zip(*parts))
    return open_credentials(data, material)
