use crate::crypto::vss::Vss;
use std::str::FromStr;

/// Test data for node vss.
/// These values correspond with key::TEST_KEYS secrets.
/// So, if you want to get node_vss for the signer of index 0, you can get by `NODE_VSS[0]`.
pub const NODE_VSS: [[&str; 5]; 5] = [
    [
        "02472012cf49fca573ca1f63deafe59df842f0bbe77e9ac7e67b211bb074b7250602472012cf49fca573ca1f63deafe59df842f0bbe77e9ac7e67b211bb074b725060003472012cf49fca573ca1f63deafe59df842f0bbe77e9ac7e67b211bb074b72506bb360eeb9d77cc606471ca455eb68331fbbdab6d009da456bef3920a61222f5835f7638e641b55dba9c5711ba47d50b8e1eefcf06d42c71708ae28dd1a038b02651456363420d02dc28ef180b66e781413133effde76d7eb7a57cffe41de3e6537325720efa3c4a847f84e72830280f2ff37758c69ade23f45d9e8c2f28f7b92a984669067dd13ecd9789da097d76f3b9c9b179f9948025db5e2ae00522f55515126b42d8c99f0b72c28ad5bf95ee38f4154f37df7d4a621b68db4f9f5c8070b472012cf49fca573ca1f63deafe59df842f0bbe77e9ac7e67b211bb074b7250644c9f1146288339f9b8e35baa1497cce04425492ff625ba9410c6df49eddccd739e10be2c059db79d50c629fe78a929d8458d064261aaa873a478ccb3b0c18f7df28e9bf75c9e4f8101b4bfb007c538499945ed651aea6122164ee9dcff02405b41ced6471dc0099a740921e10ba7d539e69153b25b2bb97257fa8dd5f0109aa52e94a550998d573aebced1eb10aaafbae5cbfb6413eed0c17f88204f2e4b13c7746199720b3bee5c3d50b9ca9e3c32e905d7058a3cb9ec899bf428ba2e0d9c7",
        "02785a891f323acd6cef0fc509bb14304410595914267c50467e51c87142acbb5e02472012cf49fca573ca1f63deafe59df842f0bbe77e9ac7e67b211bb074b725060003785a891f323acd6cef0fc509bb14304410595914267c50467e51c87142acbb5e12ab6cc10390ee6e31985e52e7d5701bed4c265dfc899cac07bc9c608ab02a74bf633344275792c413aac61fb108ba49aacb935cc637833a3d5f8bbc412a4578eec59fd45330922725e96c6c8e65980e3f571a9e99c7ea80abaabbfcc7a8541ca3bb9fb3393e593db51bf5bee44181cdf4cb1d617c0ce63682d8559f1424897b90c6c5c2684dda9a0f592fdc159c6dc744465f6de103c2ffe012c9a839034ae04a12fc2cc261586bf6b5814b1742449544aec456524b30fd530db6a76459162d785a891f323acd6cef0fc509bb14304410595914267c50467e51c87142acbb5eed54933efc6f1191ce67a1ad182a8fe412b3d9a203766353f843639e754fd1bbe5e5c0c4374a92bff9f7b7328d3baeb061b738dce75093a7a941cce96c5daf18284364f8ebabd43d3439169e92b27699e20be185ce3fb0fe44abc08fac1e25f4d256e87497f82f367abc2225cfe7d171f528160e681ae6a14df51ffdded1e96da93cc0bc30c7af4d608c6e026ca9b51f6ec61ad548117d0b98f010f847b2907e21ed09bf936cb602babaa8b37fcda1d159b6dd756c483ce982d1541e1a9bac03",
        "02ce7edc292d7b747fab2f23584bbafaffde5c8ff17cf689969614441e0527b90002472012cf49fca573ca1f63deafe59df842f0bbe77e9ac7e67b211bb074b725060003ce7edc292d7b747fab2f23584bbafaffde5c8ff17cf689969614441e0527b90015ea9fee96aed6d9c0fc2fbe0bd1883dee223b3200246ff1e21976bdbc9a0fc82ef0de1465a7dc27596e2e97087c70743c9a3686ed25882f342ab43c01d243053231904aa20a48130ce3da8a6c9c1cb96e3abf13c7fc2bc6467ff859ea85c78e0bba3cb4d94e2ed91b73b7734bc77f5a9e59e4f5dfa0358fabc24f72b3766f926e8cfbe7135e85b9463e796725b6d35f66d28929d1eda1e447260aa716b09f4acedc39c6e379af7740e5daf14fb9664872a8c3eecab1d3cd68f7d1d460344c32ce7edc292d7b747fab2f23584bbafaffde5c8ff17cf689969614441e0527b900ea156011695129263f03d041f42e77c211ddc4cdffdb900e1de689414365ec672f24627e0a688cd54fb215fef833a804ad996f9f375f049e607bb739054b6d2cf43fcba949dd1cfa0f09b21873b445536717763e09e17383c8045e95917764c5bffccad34e90d7b469cdcc73bf2897af89b2f9171561143d12fd8996bf39d1bb20b4881975fef44f40ba71f14d827f3d2f26bc6182d5341189fefe308174a542ccb96b7a0ac351921d4efea5b01362c3d6bf8e815898e699ff4b2c6ac84d18d7",
        "02d111519ba1f3013a7a613ecdcc17f4d53fbcb558b70404b5fb0c84ebb90a8d3c02472012cf49fca573ca1f63deafe59df842f0bbe77e9ac7e67b211bb074b725060003d111519ba1f3013a7a613ecdcc17f4d53fbcb558b70404b5fb0c84ebb90a8d3cb1e1ab71073241af34aabcee036dbb020b36121aebc19731ca3abeb3bbd19d9e1a7baec1441d10b7f1fbd182a4e53f9acc6f4de22485ceffe1254a77b10e9bf0a7d42cccac1043afccfd198b3cd1a0e498ece3a8f3b181f7ae3c3eb2c918e022f1502cf7a4cc817babde2cbd7f080c887ee2a4900355dcb716400a00620afc19776f6a43ba14206db88b85b80f5a3781bdfde64627b8c1ff7228b73626a648c66f3707fc6985b9b775144308ea347c7fc38099240ce9165bdbc9c5ffb5b71050d111519ba1f3013a7a613ecdcc17f4d53fbcb558b70404b5fb0c84ebb90a8d3c4e1e548ef8cdbe50cb554311fc9244fdf4c9ede5143e68ce35c5414b442e5e9128297089d43e94c182266476a1831e5eaa6668f1e00f9071df751e832475372f7c5e5ce7ecc7afd96d5feecfb8a0a28e602aea7040966c03a270aba823ea4277db9cd2bbb6f6017d04cecbcd41e758ebfd84d114b19279f867bd66ff5cd6615184dda648750e0152256f04cd7cc28d792daf3178267c6f443615b9a03d489ab3864c0d8af03257c52bd8199a308f51c114ee51d37f7033760a14253fdf76c29d",
        "03831a69b8009833ab5b0326012eaf489bfea35a7321b1ca15b11d88131423fafc02472012cf49fca573ca1f63deafe59df842f0bbe77e9ac7e67b211bb074b725060003831a69b8009833ab5b0326012eaf489bfea35a7321b1ca15b11d88131423fafc36efd8a52e2a27a50650b7e1f7db835c1f7fe5f7e587fb43e0009068b96d6ed306ae393ff8268523f6f4051a407c2e0164e14245b9499e714dd1691a5df832f1bcdd4c55bc2b958eea7b5f0de006bf6340d7ebc3de27fde6c0d639ce41f8af83f8a2f6b9f8d5dac2f971bf0f2ace4acc9ed2c70c617302755abd213421e7a1ccde12d18e5426de47339824faa5b40c307294d6835a92fa8e89ed6c1be85e9f9fd0ccd8f2fc4e0a1e5db88c74fd8a25b73076af74333671b84240b2d91d78303c831a69b8009833ab5b0326012eaf489bfea35a7321b1ca15b11d88131423fafcc910275ad1d5d85af9af481e08247ca3e0801a081a7804bc1fff6f9646928d5c531a03ee21b178dd7fef9cb537d477705f48051f94363ceae0aec0a49b1e5460a47b2bf5fbacff69679a6ba3a839a36ef9e9ab7e4efdfad4dc6903e0af9df74c67a8d43ebc28d5acce6c2531d08b144fa2a06718eede8fd855aa7970c353d7ad833fa7f087bf2d00617549ef3da4f9986955f35e98b0c9db18021c853a2ddde4c52dfd720dd715403bdb22751217d54a58d0377f4ccc0723cab9a25b9587662e",
    ],
    [
        "02472012cf49fca573ca1f63deafe59df842f0bbe77e9ac7e67b211bb074b7250602785a891f323acd6cef0fc509bb14304410595914267c50467e51c87142acbb5e0003472012cf49fca573ca1f63deafe59df842f0bbe77e9ac7e67b211bb074b72506bb360eeb9d77cc606471ca455eb68331fbbdab6d009da456bef3920a61222f5835f7638e641b55dba9c5711ba47d50b8e1eefcf06d42c71708ae28dd1a038b02651456363420d02dc28ef180b66e781413133effde76d7eb7a57cffe41de3e6537325720efa3c4a847f84e72830280f2ff37758c69ade23f45d9e8c2f28f7b92a984669067dd13ecd9789da097d76f3b9c9b179f9948025db5e2ae00522f555150a0738deae326aae4b5f3f68f56b0d1282a04d19f2c867f5b3eff0df3d47291472012cf49fca573ca1f63deafe59df842f0bbe77e9ac7e67b211bb074b7250644c9f1146288339f9b8e35baa1497cce04425492ff625ba9410c6df49eddccd739e10be2c059db79d50c629fe78a929d8458d064261aaa873a478ccb3b0c18f7df28e9bf75c9e4f8101b4bfb007c538499945ed651aea6122164ee9dcff02405b41ced6471dc0099a740921e10ba7d539e69153b25b2bb97257fa8dd5f0109aa52e94a550998d573aebced1eb10aaafbae5cbfb6413eed0c17f88204f2e4b13c9e544168dfa93b4135df83f9cc9a3652405268b61cb919119656302a200ca5e9",
        "02785a891f323acd6cef0fc509bb14304410595914267c50467e51c87142acbb5e02785a891f323acd6cef0fc509bb14304410595914267c50467e51c87142acbb5e0003785a891f323acd6cef0fc509bb14304410595914267c50467e51c87142acbb5e12ab6cc10390ee6e31985e52e7d5701bed4c265dfc899cac07bc9c608ab02a74bf633344275792c413aac61fb108ba49aacb935cc637833a3d5f8bbc412a4578eec59fd45330922725e96c6c8e65980e3f571a9e99c7ea80abaabbfcc7a8541ca3bb9fb3393e593db51bf5bee44181cdf4cb1d617c0ce63682d8559f1424897b90c6c5c2684dda9a0f592fdc159c6dc744465f6de103c2ffe012c9a839034ae05dd11579baf0270235df08dea178ea77e050a7effb5de35b54018630c3e6667b785a891f323acd6cef0fc509bb14304410595914267c50467e51c87142acbb5eed54933efc6f1191ce67a1ad182a8fe412b3d9a203766353f843639e754fd1bbe5e5c0c4374a92bff9f7b7328d3baeb061b738dce75093a7a941cce96c5daf18284364f8ebabd43d3439169e92b27699e20be185ce3fb0fe44abc08fac1e25f4d256e87497f82f367abc2225cfe7d171f528160e681ae6a14df51ffdded1e96da93cc0bc30c7af4d608c6e026ca9b51f6ec61ad548117d0b98f010f847b2907ec93bcd4176f2195d348a7d6ffbcf190b7f678d3cae457f4f45924737f6e72061",
        "02ce7edc292d7b747fab2f23584bbafaffde5c8ff17cf689969614441e0527b90002785a891f323acd6cef0fc509bb14304410595914267c50467e51c87142acbb5e0003ce7edc292d7b747fab2f23584bbafaffde5c8ff17cf689969614441e0527b90015ea9fee96aed6d9c0fc2fbe0bd1883dee223b3200246ff1e21976bdbc9a0fc82ef0de1465a7dc27596e2e97087c70743c9a3686ed25882f342ab43c01d243053231904aa20a48130ce3da8a6c9c1cb96e3abf13c7fc2bc6467ff859ea85c78e0bba3cb4d94e2ed91b73b7734bc77f5a9e59e4f5dfa0358fabc24f72b3766f926e8cfbe7135e85b9463e796725b6d35f66d28929d1eda1e447260aa716b09f4a17800cea6fdff2f962e76aa5d8cd3d0d56b1c684618e7e989a593a80645adb45ce7edc292d7b747fab2f23584bbafaffde5c8ff17cf689969614441e0527b900ea156011695129263f03d041f42e77c211ddc4cdffdb900e1de689414365ec672f24627e0a688cd54fb215fef833a804ad996f9f375f049e607bb739054b6d2cf43fcba949dd1cfa0f09b21873b445536717763e09e17383c8045e95917764c5bffccad34e90d7b469cdcc73bf2897af89b2f9171561143d12fd8996bf39d1bb20b4881975fef44f40ba71f14d827f3d2f26bc6182d5341189fefe308174a54230ab08c08e1f2457452c3dc86b99f1e1a90f8926bb6cf580f37c91d450e97240",
        "02d111519ba1f3013a7a613ecdcc17f4d53fbcb558b70404b5fb0c84ebb90a8d3c02785a891f323acd6cef0fc509bb14304410595914267c50467e51c87142acbb5e0003d111519ba1f3013a7a613ecdcc17f4d53fbcb558b70404b5fb0c84ebb90a8d3cb1e1ab71073241af34aabcee036dbb020b36121aebc19731ca3abeb3bbd19d9e1a7baec1441d10b7f1fbd182a4e53f9acc6f4de22485ceffe1254a77b10e9bf0a7d42cccac1043afccfd198b3cd1a0e498ece3a8f3b181f7ae3c3eb2c918e022f1502cf7a4cc817babde2cbd7f080c887ee2a4900355dcb716400a00620afc19776f6a43ba14206db88b85b80f5a3781bdfde64627b8c1ff7228b73626a648c6145dc8bb3ed8dfd5f23f8653d95f083487a542b8083ba3ecd2b15fa5d7c27016d111519ba1f3013a7a613ecdcc17f4d53fbcb558b70404b5fb0c84ebb90a8d3c4e1e548ef8cdbe50cb554311fc9244fdf4c9ede5143e68ce35c5414b442e5e9128297089d43e94c182266476a1831e5eaa6668f1e00f9071df751e832475372f7c5e5ce7ecc7afd96d5feecfb8a0a28e602aea7040966c03a270aba823ea4277db9cd2bbb6f6017d04cecbcd41e758ebfd84d114b19279f867bd66ff5cd6615184dda648750e0152256f04cd7cc28d792daf3178267c6f443615b9a03d489ab3dbc16b7dddca34ca9824720a58dbab806909456db31f8b64eec33b49e816c510",
        "03831a69b8009833ab5b0326012eaf489bfea35a7321b1ca15b11d88131423fafc02785a891f323acd6cef0fc509bb14304410595914267c50467e51c87142acbb5e0003831a69b8009833ab5b0326012eaf489bfea35a7321b1ca15b11d88131423fafc36efd8a52e2a27a50650b7e1f7db835c1f7fe5f7e587fb43e0009068b96d6ed306ae393ff8268523f6f4051a407c2e0164e14245b9499e714dd1691a5df832f1bcdd4c55bc2b958eea7b5f0de006bf6340d7ebc3de27fde6c0d639ce41f8af83f8a2f6b9f8d5dac2f971bf0f2ace4acc9ed2c70c617302755abd213421e7a1ccde12d18e5426de47339824faa5b40c307294d6835a92fa8e89ed6c1be85e9f9f164a967dcc022b1112a6923748bd713b5f51dc13b2425faaa1031f3e917ed032831a69b8009833ab5b0326012eaf489bfea35a7321b1ca15b11d88131423fafcc910275ad1d5d85af9af481e08247ca3e0801a081a7804bc1fff6f9646928d5c531a03ee21b178dd7fef9cb537d477705f48051f94363ceae0aec0a49b1e5460a47b2bf5fbacff69679a6ba3a839a36ef9e9ab7e4efdfad4dc6903e0af9df74c67a8d43ebc28d5acce6c2531d08b144fa2a06718eede8fd855aa7970c353d7ad833fa7f087bf2d00617549ef3da4f9986955f35e98b0c9db18021c853a2ddde44a2564abe0b33f432b95aeada0efade4a609b95854522b69e659d5a6a3f60084",
    ],
    [
        "02472012cf49fca573ca1f63deafe59df842f0bbe77e9ac7e67b211bb074b7250602ce7edc292d7b747fab2f23584bbafaffde5c8ff17cf689969614441e0527b9000003472012cf49fca573ca1f63deafe59df842f0bbe77e9ac7e67b211bb074b72506bb360eeb9d77cc606471ca455eb68331fbbdab6d009da456bef3920a61222f5835f7638e641b55dba9c5711ba47d50b8e1eefcf06d42c71708ae28dd1a038b02651456363420d02dc28ef180b66e781413133effde76d7eb7a57cffe41de3e6537325720efa3c4a847f84e72830280f2ff37758c69ade23f45d9e8c2f28f7b92a984669067dd13ecd9789da097d76f3b9c9b179f9948025db5e2ae00522f5551dd02ccc0789bca72691bcd36624986a94e36b7b992b1eb12c626db837faccfcf472012cf49fca573ca1f63deafe59df842f0bbe77e9ac7e67b211bb074b7250644c9f1146288339f9b8e35baa1497cce04425492ff625ba9410c6df49eddccd739e10be2c059db79d50c629fe78a929d8458d064261aaa873a478ccb3b0c18f7df28e9bf75c9e4f8101b4bfb007c538499945ed651aea6122164ee9dcff02405b41ced6471dc0099a740921e10ba7d539e69153b25b2bb97257fa8dd5f0109aa52e94a550998d573aebced1eb10aaafbae5cbfb6413eed0c17f88204f2e4b13c9694e8d5df204c7b16ab6fb0c7c13a8630d642407d66c51cdd842a20c232186a",
        "02785a891f323acd6cef0fc509bb14304410595914267c50467e51c87142acbb5e02ce7edc292d7b747fab2f23584bbafaffde5c8ff17cf689969614441e0527b9000003785a891f323acd6cef0fc509bb14304410595914267c50467e51c87142acbb5e12ab6cc10390ee6e31985e52e7d5701bed4c265dfc899cac07bc9c608ab02a74bf633344275792c413aac61fb108ba49aacb935cc637833a3d5f8bbc412a4578eec59fd45330922725e96c6c8e65980e3f571a9e99c7ea80abaabbfcc7a8541ca3bb9fb3393e593db51bf5bee44181cdf4cb1d617c0ce63682d8559f1424897b90c6c5c2684dda9a0f592fdc159c6dc744465f6de103c2ffe012c9a839034ae048f634cb97eec62fe4048862825e09646bac1e3062c908d2b06c87d8242f4fdb785a891f323acd6cef0fc509bb14304410595914267c50467e51c87142acbb5eed54933efc6f1191ce67a1ad182a8fe412b3d9a203766353f843639e754fd1bbe5e5c0c4374a92bff9f7b7328d3baeb061b738dce75093a7a941cce96c5daf18284364f8ebabd43d3439169e92b27699e20be185ce3fb0fe44abc08fac1e25f4d256e87497f82f367abc2225cfe7d171f528160e681ae6a14df51ffdded1e96da93cc0bc30c7af4d608c6e026ca9b51f6ec61ad548117d0b98f010f847b2907ee83061a0fc4dcfa246e78c8d904a4df31d9cbf0baf1e353cdadf6184bf24bce8",
        "02ce7edc292d7b747fab2f23584bbafaffde5c8ff17cf689969614441e0527b90002ce7edc292d7b747fab2f23584bbafaffde5c8ff17cf689969614441e0527b9000003ce7edc292d7b747fab2f23584bbafaffde5c8ff17cf689969614441e0527b90015ea9fee96aed6d9c0fc2fbe0bd1883dee223b3200246ff1e21976bdbc9a0fc82ef0de1465a7dc27596e2e97087c70743c9a3686ed25882f342ab43c01d243053231904aa20a48130ce3da8a6c9c1cb96e3abf13c7fc2bc6467ff859ea85c78e0bba3cb4d94e2ed91b73b7734bc77f5a9e59e4f5dfa0358fabc24f72b3766f926e8cfbe7135e85b9463e796725b6d35f66d28929d1eda1e447260aa716b09f4a8856625071f27acbf64508b58968d71ed4a933ef5adfb5de4fffd06c442d45eace7edc292d7b747fab2f23584bbafaffde5c8ff17cf689969614441e0527b900ea156011695129263f03d041f42e77c211ddc4cdffdb900e1de689414365ec672f24627e0a688cd54fb215fef833a804ad996f9f375f049e607bb739054b6d2cf43fcba949dd1cfa0f09b21873b445536717763e09e17383c8045e95917764c5bffccad34e90d7b469cdcc73bf2897af89b2f9171561143d12fd8996bf39d1bb20b4881975fef44f40ba71f14d827f3d2f26bc6182d5341189fefe308174a5427d69eeedbd53c809e75763d044665a82f3cc1442fe9d9862dfd47294732ab9cf",
        "02d111519ba1f3013a7a613ecdcc17f4d53fbcb558b70404b5fb0c84ebb90a8d3c02ce7edc292d7b747fab2f23584bbafaffde5c8ff17cf689969614441e0527b9000003d111519ba1f3013a7a613ecdcc17f4d53fbcb558b70404b5fb0c84ebb90a8d3cb1e1ab71073241af34aabcee036dbb020b36121aebc19731ca3abeb3bbd19d9e1a7baec1441d10b7f1fbd182a4e53f9acc6f4de22485ceffe1254a77b10e9bf0a7d42cccac1043afccfd198b3cd1a0e498ece3a8f3b181f7ae3c3eb2c918e022f1502cf7a4cc817babde2cbd7f080c887ee2a4900355dcb716400a00620afc19776f6a43ba14206db88b85b80f5a3781bdfde64627b8c1ff7228b73626a648c69a4bea044c257de3080841c0ccc0e1176799a4e572fc6bb85e928a53ebf254b4d111519ba1f3013a7a613ecdcc17f4d53fbcb558b70404b5fb0c84ebb90a8d3c4e1e548ef8cdbe50cb554311fc9244fdf4c9ede5143e68ce35c5414b442e5e9128297089d43e94c182266476a1831e5eaa6668f1e00f9071df751e832475372f7c5e5ce7ecc7afd96d5feecfb8a0a28e602aea7040966c03a270aba823ea4277db9cd2bbb6f6017d04cecbcd41e758ebfd84d114b19279f867bd66ff5cd6615184dda648750e0152256f04cd7cc28d792daf3178267c6f443615b9a03d489ab355887210fc9b8b88b45e917079a3cf439bd40f8bc951e502f403e34964461338",
        "03831a69b8009833ab5b0326012eaf489bfea35a7321b1ca15b11d88131423fafc02ce7edc292d7b747fab2f23584bbafaffde5c8ff17cf689969614441e0527b9000003831a69b8009833ab5b0326012eaf489bfea35a7321b1ca15b11d88131423fafc36efd8a52e2a27a50650b7e1f7db835c1f7fe5f7e587fb43e0009068b96d6ed306ae393ff8268523f6f4051a407c2e0164e14245b9499e714dd1691a5df832f1bcdd4c55bc2b958eea7b5f0de006bf6340d7ebc3de27fde6c0d639ce41f8af83f8a2f6b9f8d5dac2f971bf0f2ace4acc9ed2c70c617302755abd213421e7a1ccde12d18e5426de47339824faa5b40c307294d6835a92fa8e89ed6c1be85e9f9fac330a36a61de53f45580d73a948a3087407014eb2284860208c92dc703f69ef831a69b8009833ab5b0326012eaf489bfea35a7321b1ca15b11d88131423fafcc910275ad1d5d85af9af481e08247ca3e0801a081a7804bc1fff6f9646928d5c531a03ee21b178dd7fef9cb537d477705f48051f94363ceae0aec0a49b1e5460a47b2bf5fbacff69679a6ba3a839a36ef9e9ab7e4efdfad4dc6903e0af9df74c67a8d43ebc28d5acce6c2531d08b144fa2a06718eede8fd855aa7970c353d7ad833fa7f087bf2d00617549ef3da4f9986955f35e98b0c9db18021c853a2ddde4b32c64174192fba1a8a1a87ce4d8c94ca5a15a9c4df90f740db724f5282f8b3a",
    ],
    [
        "02472012cf49fca573ca1f63deafe59df842f0bbe77e9ac7e67b211bb074b7250602d111519ba1f3013a7a613ecdcc17f4d53fbcb558b70404b5fb0c84ebb90a8d3c0003472012cf49fca573ca1f63deafe59df842f0bbe77e9ac7e67b211bb074b72506bb360eeb9d77cc606471ca455eb68331fbbdab6d009da456bef3920a61222f5835f7638e641b55dba9c5711ba47d50b8e1eefcf06d42c71708ae28dd1a038b02651456363420d02dc28ef180b66e781413133effde76d7eb7a57cffe41de3e6537325720efa3c4a847f84e72830280f2ff37758c69ade23f45d9e8c2f28f7b92a984669067dd13ecd9789da097d76f3b9c9b179f9948025db5e2ae00522f5551f64dbfc535c3dc0db95a391b72376518f8cc2f4f231c33a03772ebcdc91add84472012cf49fca573ca1f63deafe59df842f0bbe77e9ac7e67b211bb074b7250644c9f1146288339f9b8e35baa1497cce04425492ff625ba9410c6df49eddccd739e10be2c059db79d50c629fe78a929d8458d064261aaa873a478ccb3b0c18f7df28e9bf75c9e4f8101b4bfb007c538499945ed651aea6122164ee9dcff02405b41ced6471dc0099a740921e10ba7d539e69153b25b2bb97257fa8dd5f0109aa52e94a550998d573aebced1eb10aaafbae5cbfb6413eed0c17f88204f2e4b13c60080fde1f18f2936638cec19b58cfca61e8fcf7c5d4a2ea6f49306f8951314a",
        "02785a891f323acd6cef0fc509bb14304410595914267c50467e51c87142acbb5e02d111519ba1f3013a7a613ecdcc17f4d53fbcb558b70404b5fb0c84ebb90a8d3c0003785a891f323acd6cef0fc509bb14304410595914267c50467e51c87142acbb5e12ab6cc10390ee6e31985e52e7d5701bed4c265dfc899cac07bc9c608ab02a74bf633344275792c413aac61fb108ba49aacb935cc637833a3d5f8bbc412a4578eec59fd45330922725e96c6c8e65980e3f571a9e99c7ea80abaabbfcc7a8541ca3bb9fb3393e593db51bf5bee44181cdf4cb1d617c0ce63682d8559f1424897b90c6c5c2684dda9a0f592fdc159c6dc744465f6de103c2ffe012c9a839034ae00b825a22595d35f50125ffd6b9f1a15ae6c12717888ca163684ebb9d8533d24d785a891f323acd6cef0fc509bb14304410595914267c50467e51c87142acbb5eed54933efc6f1191ce67a1ad182a8fe412b3d9a203766353f843639e754fd1bbe5e5c0c4374a92bff9f7b7328d3baeb061b738dce75093a7a941cce96c5daf18284364f8ebabd43d3439169e92b27699e20be185ce3fb0fe44abc08fac1e25f4d256e87497f82f367abc2225cfe7d171f528160e681ae6a14df51ffdded1e96da93cc0bc30c7af4d608c6e026ca9b51f6ec61ad548117d0b98f010f847b2907e7ecac6de237fd8d1f1d1d60c3d3f4088345672e26ed25eb242b8a30473548198",
        "02ce7edc292d7b747fab2f23584bbafaffde5c8ff17cf689969614441e0527b90002d111519ba1f3013a7a613ecdcc17f4d53fbcb558b70404b5fb0c84ebb90a8d3c0003ce7edc292d7b747fab2f23584bbafaffde5c8ff17cf689969614441e0527b90015ea9fee96aed6d9c0fc2fbe0bd1883dee223b3200246ff1e21976bdbc9a0fc82ef0de1465a7dc27596e2e97087c70743c9a3686ed25882f342ab43c01d243053231904aa20a48130ce3da8a6c9c1cb96e3abf13c7fc2bc6467ff859ea85c78e0bba3cb4d94e2ed91b73b7734bc77f5a9e59e4f5dfa0358fabc24f72b3766f926e8cfbe7135e85b9463e796725b6d35f66d28929d1eda1e447260aa716b09f4a215f39f8e9b146eefafeb520618c347f77315262581439270a46d67e5f3f099fce7edc292d7b747fab2f23584bbafaffde5c8ff17cf689969614441e0527b900ea156011695129263f03d041f42e77c211ddc4cdffdb900e1de689414365ec672f24627e0a688cd54fb215fef833a804ad996f9f375f049e607bb739054b6d2cf43fcba949dd1cfa0f09b21873b445536717763e09e17383c8045e95917764c5bffccad34e90d7b469cdcc73bf2897af89b2f9171561143d12fd8996bf39d1bb20b4881975fef44f40ba71f14d827f3d2f26bc6182d5341189fefe308174a542b2f61e0198613caa03d070bd3a789ca8fc4652ef72e22f040480701e5edaae43",
        "02d111519ba1f3013a7a613ecdcc17f4d53fbcb558b70404b5fb0c84ebb90a8d3c02d111519ba1f3013a7a613ecdcc17f4d53fbcb558b70404b5fb0c84ebb90a8d3c0003d111519ba1f3013a7a613ecdcc17f4d53fbcb558b70404b5fb0c84ebb90a8d3cb1e1ab71073241af34aabcee036dbb020b36121aebc19731ca3abeb3bbd19d9e1a7baec1441d10b7f1fbd182a4e53f9acc6f4de22485ceffe1254a77b10e9bf0a7d42cccac1043afccfd198b3cd1a0e498ece3a8f3b181f7ae3c3eb2c918e022f1502cf7a4cc817babde2cbd7f080c887ee2a4900355dcb716400a00620afc19776f6a43ba14206db88b85b80f5a3781bdfde64627b8c1ff7228b73626a648c601016bd7916b93deb66e754fc45a072aee0005deee9a2d46ffc888f051da3ba8d111519ba1f3013a7a613ecdcc17f4d53fbcb558b70404b5fb0c84ebb90a8d3c4e1e548ef8cdbe50cb554311fc9244fdf4c9ede5143e68ce35c5414b442e5e9128297089d43e94c182266476a1831e5eaa6668f1e00f9071df751e832475372f7c5e5ce7ecc7afd96d5feecfb8a0a28e602aea7040966c03a270aba823ea4277db9cd2bbb6f6017d04cecbcd41e758ebfd84d114b19279f867bd66ff5cd6615184dda648750e0152256f04cd7cc28d792daf3178267c6f443615b9a03d489ab3f3a121444ca65bff808677cc92e7bd0822ac69fb209880c7997ada57f4712f97",
        "03831a69b8009833ab5b0326012eaf489bfea35a7321b1ca15b11d88131423fafc02d111519ba1f3013a7a613ecdcc17f4d53fbcb558b70404b5fb0c84ebb90a8d3c0003831a69b8009833ab5b0326012eaf489bfea35a7321b1ca15b11d88131423fafc36efd8a52e2a27a50650b7e1f7db835c1f7fe5f7e587fb43e0009068b96d6ed306ae393ff8268523f6f4051a407c2e0164e14245b9499e714dd1691a5df832f1bcdd4c55bc2b958eea7b5f0de006bf6340d7ebc3de27fde6c0d639ce41f8af83f8a2f6b9f8d5dac2f971bf0f2ace4acc9ed2c70c617302755abd213421e7a1ccde12d18e5426de47339824faa5b40c307294d6835a92fa8e89ed6c1be85e9f9f9286341d8aa138a8f5ccfe2a1f2bbb20f9386557d456eb6141385099194d7af1831a69b8009833ab5b0326012eaf489bfea35a7321b1ca15b11d88131423fafcc910275ad1d5d85af9af481e08247ca3e0801a081a7804bc1fff6f9646928d5c531a03ee21b178dd7fef9cb537d477705f48051f94363ceae0aec0a49b1e5460a47b2bf5fbacff69679a6ba3a839a36ef9e9ab7e4efdfad4dc6903e0af9df74c67a8d43ebc28d5acce6c2531d08b144fa2a06718eede8fd855aa7970c353d7ad833fa7f087bf2d00617549ef3da4f9986955f35e98b0c9db18021c853a2ddde40042fbb430764a5bb2ff0fe2ddd32784e239617ddb2f72cac12cd32d81c783ce",
    ],
    [
        "02472012cf49fca573ca1f63deafe59df842f0bbe77e9ac7e67b211bb074b7250603831a69b8009833ab5b0326012eaf489bfea35a7321b1ca15b11d88131423fafc0003472012cf49fca573ca1f63deafe59df842f0bbe77e9ac7e67b211bb074b72506bb360eeb9d77cc606471ca455eb68331fbbdab6d009da456bef3920a61222f5835f7638e641b55dba9c5711ba47d50b8e1eefcf06d42c71708ae28dd1a038b02651456363420d02dc28ef180b66e781413133effde76d7eb7a57cffe41de3e6537325720efa3c4a847f84e72830280f2ff37758c69ade23f45d9e8c2f28f7b92a984669067dd13ecd9789da097d76f3b9c9b179f9948025db5e2ae00522f55519c814c9c225b5b7cd57137a5bf204c2027ea6b92506b6027af232fecd01e9bb0472012cf49fca573ca1f63deafe59df842f0bbe77e9ac7e67b211bb074b7250644c9f1146288339f9b8e35baa1497cce04425492ff625ba9410c6df49eddccd739e10be2c059db79d50c629fe78a929d8458d064261aaa873a478ccb3b0c18f7df28e9bf75c9e4f8101b4bfb007c538499945ed651aea6122164ee9dcff02405b41ced6471dc0099a740921e10ba7d539e69153b25b2bb97257fa8dd5f0109aa52e94a550998d573aebced1eb10aaafbae5cbfb6413eed0c17f88204f2e4b13cfaadb6819f932d8a2487a12c4760f61d8e3975c2a54b52b60b77a1a345a031ca",
        "02785a891f323acd6cef0fc509bb14304410595914267c50467e51c87142acbb5e03831a69b8009833ab5b0326012eaf489bfea35a7321b1ca15b11d88131423fafc0003785a891f323acd6cef0fc509bb14304410595914267c50467e51c87142acbb5e12ab6cc10390ee6e31985e52e7d5701bed4c265dfc899cac07bc9c608ab02a74bf633344275792c413aac61fb108ba49aacb935cc637833a3d5f8bbc412a4578eec59fd45330922725e96c6c8e65980e3f571a9e99c7ea80abaabbfcc7a8541ca3bb9fb3393e593db51bf5bee44181cdf4cb1d617c0ce63682d8559f1424897b90c6c5c2684dda9a0f592fdc159c6dc744465f6de103c2ffe012c9a839034ae0a575857dff3b76518d436f3b4833b25a0c3e9f8c1bf14d493b7a800db72a2f12785a891f323acd6cef0fc509bb14304410595914267c50467e51c87142acbb5eed54933efc6f1191ce67a1ad182a8fe412b3d9a203766353f843639e754fd1bbe5e5c0c4374a92bff9f7b7328d3baeb061b738dce75093a7a941cce96c5daf18284364f8ebabd43d3439169e92b27699e20be185ce3fb0fe44abc08fac1e25f4d256e87497f82f367abc2225cfe7d171f528160e681ae6a14df51ffdded1e96da93cc0bc30c7af4d608c6e026ca9b51f6ec61ad548117d0b98f010f847b2907e8d0afcf8ec8834ec354959ec02adf0c97e4385a79caa9beb3cf06a43e3acafb2",
        "02ce7edc292d7b747fab2f23584bbafaffde5c8ff17cf689969614441e0527b90003831a69b8009833ab5b0326012eaf489bfea35a7321b1ca15b11d88131423fafc0003ce7edc292d7b747fab2f23584bbafaffde5c8ff17cf689969614441e0527b90015ea9fee96aed6d9c0fc2fbe0bd1883dee223b3200246ff1e21976bdbc9a0fc82ef0de1465a7dc27596e2e97087c70743c9a3686ed25882f342ab43c01d243053231904aa20a48130ce3da8a6c9c1cb96e3abf13c7fc2bc6467ff859ea85c78e0bba3cb4d94e2ed91b73b7734bc77f5a9e59e4f5dfa0358fabc24f72b3766f926e8cfbe7135e85b9463e796725b6d35f66d28929d1eda1e447260aa716b09f4ae29a93e3d71c576271146fe66137552cb3a7dbaab7bd48ea48d309d055fca8e6ce7edc292d7b747fab2f23584bbafaffde5c8ff17cf689969614441e0527b900ea156011695129263f03d041f42e77c211ddc4cdffdb900e1de689414365ec672f24627e0a688cd54fb215fef833a804ad996f9f375f049e607bb739054b6d2cf43fcba949dd1cfa0f09b21873b445536717763e09e17383c8045e95917764c5bffccad34e90d7b469cdcc73bf2897af89b2f9171561143d12fd8996bf39d1bb20b4881975fef44f40ba71f14d827f3d2f26bc6182d5341189fefe308174a542d14f95fc1f4782379a97648f4dd0b853c27e452c183ab96461808a7213f94f9c",
        "02d111519ba1f3013a7a613ecdcc17f4d53fbcb558b70404b5fb0c84ebb90a8d3c03831a69b8009833ab5b0326012eaf489bfea35a7321b1ca15b11d88131423fafc0003d111519ba1f3013a7a613ecdcc17f4d53fbcb558b70404b5fb0c84ebb90a8d3cb1e1ab71073241af34aabcee036dbb020b36121aebc19731ca3abeb3bbd19d9e1a7baec1441d10b7f1fbd182a4e53f9acc6f4de22485ceffe1254a77b10e9bf0a7d42cccac1043afccfd198b3cd1a0e498ece3a8f3b181f7ae3c3eb2c918e022f1502cf7a4cc817babde2cbd7f080c887ee2a4900355dcb716400a00620afc19776f6a43ba14206db88b85b80f5a3781bdfde64627b8c1ff7228b73626a648c6487e4e350eab21c8fd722100c02a7a6c90361f71d9a6291035f81894a9e6a774d111519ba1f3013a7a613ecdcc17f4d53fbcb558b70404b5fb0c84ebb90a8d3c4e1e548ef8cdbe50cb554311fc9244fdf4c9ede5143e68ce35c5414b442e5e9128297089d43e94c182266476a1831e5eaa6668f1e00f9071df751e832475372f7c5e5ce7ecc7afd96d5feecfb8a0a28e602aea7040966c03a270aba823ea4277db9cd2bbb6f6017d04cecbcd41e758ebfd84d114b19279f867bd66ff5cd6615184dda648750e0152256f04cd7cc28d792daf3178267c6f443615b9a03d489ab3b60b7917cdeaa62efc9c251ea4a774d088349aee5a621e3b5f83635bf82b97ab",
        "03831a69b8009833ab5b0326012eaf489bfea35a7321b1ca15b11d88131423fafc03831a69b8009833ab5b0326012eaf489bfea35a7321b1ca15b11d88131423fafc0003831a69b8009833ab5b0326012eaf489bfea35a7321b1ca15b11d88131423fafc36efd8a52e2a27a50650b7e1f7db835c1f7fe5f7e587fb43e0009068b96d6ed306ae393ff8268523f6f4051a407c2e0164e14245b9499e714dd1691a5df832f1bcdd4c55bc2b958eea7b5f0de006bf6340d7ebc3de27fde6c0d639ce41f8af83f8a2f6b9f8d5dac2f971bf0f2ace4acc9ed2c70c617302755abd213421e7a1ccde12d18e5426de47339824faa5b40c307294d6835a92fa8e89ed6c1be85e9f9fc9441432798c254e2405645aaa66b983a994e515c816e8e9c2d8b7015cdf4479831a69b8009833ab5b0326012eaf489bfea35a7321b1ca15b11d88131423fafcc910275ad1d5d85af9af481e08247ca3e0801a081a7804bc1fff6f9646928d5c531a03ee21b178dd7fef9cb537d477705f48051f94363ceae0aec0a49b1e5460a47b2bf5fbacff69679a6ba3a839a36ef9e9ab7e4efdfad4dc6903e0af9df74c67a8d43ebc28d5acce6c2531d08b144fa2a06718eede8fd855aa7970c353d7ad833fa7f087bf2d00617549ef3da4f9986955f35e98b0c9db18021c853a2ddde431692b82ad5d2b714aade4df8bdec88ad12f87ca5a8695e5805f9d69512a6cc2",
    ]
];

pub fn node_vss(i: usize) -> Vec<Vss> {
    assert!(i < 5);
    NODE_VSS[i]
        .iter()
        .map(|vss| Vss::from_str(vss).unwrap())
        .collect()
}