var group__QUIC =
[
    [ "Crypt", "group__Crypt.html", "group__Crypt" ],
    [ "Connection", "group__QUIC__Connection.html", "group__QUIC__Connection" ],
    [ "Wire", "group__QUIC__Wire.html", "group__QUIC__Wire" ],
    [ "Frame Types", "group__QUIC__FRAME__TYPES.html", "group__QUIC__FRAME__TYPES" ],
    [ "Drive Functions", "group__QUIC__Drive.html", "group__QUIC__Drive" ],
    [ "Internal", "group__QUIC__Internal.html", "group__QUIC__Internal" ],
    [ "YAWT_Q_IoVec_t", "structYAWT__Q__IoVec__t.html", [
      [ "buf", "structYAWT__Q__IoVec__t.html#a67438931c8d644b317de1a5298472f64", null ],
      [ "len", "structYAWT__Q__IoVec__t.html#ac1b74315ddf01f35549269a6ae31b7d1", null ]
    ] ],
    [ "YAWT_Q_FlowControlInfo_t", "structYAWT__Q__FlowControlInfo__t.html", [
      [ "consumed", "structYAWT__Q__FlowControlInfo__t.html#a1c751e717e47fddd57ca500b680d03c8", null ],
      [ "current_limit", "structYAWT__Q__FlowControlInfo__t.html#a7027009196acedea1e904e367cd352f7", null ],
      [ "stream_id", "structYAWT__Q__FlowControlInfo__t.html#aec5c6199d2718257d1b861d1e805adf5", null ],
      [ "type", "structYAWT__Q__FlowControlInfo__t.html#a9b8434e1222cacc7c7b1cfe3511ae1f7", null ]
    ] ],
    [ "YAWT_Q_EventParam_t", "unionYAWT__Q__EventParam__t.html", [
      [ "app_error_code", "unionYAWT__Q__EventParam__t.html#a8566a7c9fc39135f842aae6739053680", null ],
      [ "buf", "unionYAWT__Q__EventParam__t.html#ae2b4897baa309791915786b849c23b7f", null ],
      [ "data", "unionYAWT__Q__EventParam__t.html#afb5c1cc135e6144b8b367ae580449b86", null ],
      [ "error_code", "unionYAWT__Q__EventParam__t.html#a315c99c5a6c2a82a9489276766005145", null ],
      [ "final_size", "unionYAWT__Q__EventParam__t.html#a84376d8fb0e11ea380c6b8045002864e", null ],
      [ "frame", "unionYAWT__Q__EventParam__t.html#a5663399a83ccc4186c0314f7ba3a05b9", null ],
      [ "info", "unionYAWT__Q__EventParam__t.html#a88ef750abc34857caf413c15890f23e6", null ],
      [ "len", "unionYAWT__Q__EventParam__t.html#aaaa839e477026abb6da7db1324938565", null ],
      [ "P_EVT_CLOSE", "unionYAWT__Q__EventParam__t.html#a645d476c39510561a7899bacafd0af33", null ],
      [ "P_EVT_CONNECTED", "unionYAWT__Q__EventParam__t.html#a49398fa0042e42e8b88e507e7dc746fa", null ],
      [ "P_EVT_DATAGRAM", "unionYAWT__Q__EventParam__t.html#acf047578fdf2ee7aa17b189692ab6eac", null ],
      [ "P_EVT_FLOW_CONTROL", "unionYAWT__Q__EventParam__t.html#ae87782055032be83a84cdea4b15370b5", null ],
      [ "P_EVT_STREAM", "unionYAWT__Q__EventParam__t.html#a4e59a99db9baa65231e36b5903346de2", null ],
      [ "P_EVT_STREAM_RESET", "unionYAWT__Q__EventParam__t.html#ab1840a7bfbdc9580173eebfe402fc2c0", null ],
      [ "P_EVT_STREAM_STOP_SENDING", "unionYAWT__Q__EventParam__t.html#a6aa96f37c37f952a265413322afd39f2", null ],
      [ "P_EVT_TX", "unionYAWT__Q__EventParam__t.html#aa40e34bd6258a31e32c7460d208fa199", null ],
      [ "peer", "unionYAWT__Q__EventParam__t.html#a172af9f0b21ac094c281ca6d532f81d1", null ],
      [ "reason", "unionYAWT__Q__EventParam__t.html#a075f3ff32adf58616d7b7f5aa9f56107", null ],
      [ "stream_id", "unionYAWT__Q__EventParam__t.html#a48c0d736d01da1001431eda66c12ee8f", null ],
      [ "stream_ud", "unionYAWT__Q__EventParam__t.html#ad321d0aa1b187c17c98062ce1ece512e", null ]
    ] ],
    [ "YAWT_Q_EventHandler_t", "group__QUIC.html#ga9e879dcdafa95d89ee1852c5bac459c5", null ],
    [ "YAWT_Q_Con_Role_t", "group__QUIC.html#gaad74cce064389d6cda79d9bf17d0a824", [
      [ "YAWT_Q_ROLE_CLIENT", "group__QUIC.html#ggaad74cce064389d6cda79d9bf17d0a824a97962c2efe8a5b1fad745ce8c5b70733", null ],
      [ "YAWT_Q_ROLE_SERVER", "group__QUIC.html#ggaad74cce064389d6cda79d9bf17d0a824a5f82b5504ba3abc21780ee7f9a992b75", null ]
    ] ],
    [ "YAWT_Q_ConnState_t", "group__QUIC.html#ga5fd9150f52776bb1282dd9a9e77b2616", [
      [ "YAWT_Q_STATE_OPEN", "group__QUIC.html#gga5fd9150f52776bb1282dd9a9e77b2616ae18dbc5372d365f22fa1950755eec572", null ],
      [ "YAWT_Q_STATE_SELF_CLOSE_CLOSING", "group__QUIC.html#gga5fd9150f52776bb1282dd9a9e77b2616a3c9fa2e83d870e053ec737ae3fbb0ee0", null ],
      [ "YAWT_Q_STATE_PEER_CLOSE_DRAINING", "group__QUIC.html#gga5fd9150f52776bb1282dd9a9e77b2616a9453271836fb9f7079bb16fb2fa80148", null ],
      [ "YAWT_Q_STATE_ADDR_VALIDATED", "group__QUIC.html#gga5fd9150f52776bb1282dd9a9e77b2616aad9b8d053d9ffc179a0e34a6388a56fe", null ]
    ] ],
    [ "YAWT_Q_EventType_t", "group__QUIC.html#ga8f207db1067de78b254ce521377215dd", [
      [ "YAWT_Q_EVT_CONNECTED", "group__QUIC.html#gga8f207db1067de78b254ce521377215ddad4d927b8985a2b7503d3686b9fa20052", null ],
      [ "YAWT_Q_EVT_STREAM", "group__QUIC.html#gga8f207db1067de78b254ce521377215ddaece56cb3c46e1fc048d9484be680218f", null ],
      [ "YAWT_Q_EVT_DATAGRAM", "group__QUIC.html#gga8f207db1067de78b254ce521377215dda685cfbcc2598f57d6a3f05474263a24b", null ],
      [ "YAWT_Q_EVT_CLOSE", "group__QUIC.html#gga8f207db1067de78b254ce521377215dda959320b9613268697f41d6665edc7b6b", null ],
      [ "YAWT_Q_EVT_TX", "group__QUIC.html#gga8f207db1067de78b254ce521377215dda66e36cca85a87053b7a0ba9655cf993a", null ],
      [ "YAWT_Q_EVT_STREAM_RESET", "group__QUIC.html#gga8f207db1067de78b254ce521377215ddae4e8ebe9ce5be0e4cb9632e541c97359", null ],
      [ "YAWT_Q_EVT_STREAM_STOP_SENDING", "group__QUIC.html#gga8f207db1067de78b254ce521377215dda3682abd535b299346b5a45a0cd841429", null ],
      [ "YAWT_Q_EVT_FLOW_CONTROL", "group__QUIC.html#gga8f207db1067de78b254ce521377215ddad64fed266f156e1121c5ff825fa2013e", null ]
    ] ],
    [ "YAWT_Q_FlowControlType_t", "group__QUIC.html#gaba436bfd516d24381d1b14e3af7b656a", [
      [ "YAWT_Q_FC_UNSET", "group__QUIC.html#ggaba436bfd516d24381d1b14e3af7b656aae63894364d583b52a69d05acd374b4ee", null ],
      [ "YAWT_Q_FC_STREAM_RX", "group__QUIC.html#ggaba436bfd516d24381d1b14e3af7b656aa60b461a9a02827103869261d980c8ceb", null ],
      [ "YAWT_Q_FC_STREAM_TX", "group__QUIC.html#ggaba436bfd516d24381d1b14e3af7b656aadbc2d798b9108856ee8e8467a8ff49c7", null ],
      [ "YAWT_Q_FC_CONN_RX", "group__QUIC.html#ggaba436bfd516d24381d1b14e3af7b656aaa41c58fff93522259361935e46c4fb21", null ],
      [ "YAWT_Q_FC_CONN_TX", "group__QUIC.html#ggaba436bfd516d24381d1b14e3af7b656aafdef2b9f9adc7c70e9b41f331904f2f5", null ]
    ] ],
    [ "YAWT_Q_Frame_Type_t", "group__QUIC.html#ga57a79159b86da14e34eb450d26fe6072", [
      [ "YAWT_Q_FRAME_PADDING", "group__QUIC.html#gga57a79159b86da14e34eb450d26fe6072a4d41655c2630c52b7279c53810821c5b", null ],
      [ "YAWT_Q_FRAME_PING", "group__QUIC.html#gga57a79159b86da14e34eb450d26fe6072aee21a70eb24ff62447ced1c5e6a0ab7a", null ],
      [ "YAWT_Q_FRAME_ACK", "group__QUIC.html#gga57a79159b86da14e34eb450d26fe6072ac479f6b3cf85ca02374b815af87c831f", null ],
      [ "YAWT_Q_FRAME_ACK_ECN", "group__QUIC.html#gga57a79159b86da14e34eb450d26fe6072a95a8db77d60c164abdfc99f6ed13748b", null ],
      [ "YAWT_Q_FRAME_RESET_STREAM", "group__QUIC.html#gga57a79159b86da14e34eb450d26fe6072ad5c2e89f7fa1baea6c67d00dbca5e19c", null ],
      [ "YAWT_Q_FRAME_STOP_SENDING", "group__QUIC.html#gga57a79159b86da14e34eb450d26fe6072aec2e182979f6e06d5c3de71f85f7cd55", null ],
      [ "YAWT_Q_FRAME_CRYPTO", "group__QUIC.html#gga57a79159b86da14e34eb450d26fe6072aed793fff5b01320203d59d91830a3002", null ],
      [ "YAWT_Q_FRAME_NEW_TOKEN", "group__QUIC.html#gga57a79159b86da14e34eb450d26fe6072a719a6bde025c0b2fd4c51af74c8b6773", null ],
      [ "YAWT_Q_FRAME_STREAM", "group__QUIC.html#gga57a79159b86da14e34eb450d26fe6072a1fd6881e4d7e79ec818e6394a23a61f1", null ],
      [ "YAWT_Q_FRAME_MAX_DATA", "group__QUIC.html#gga57a79159b86da14e34eb450d26fe6072a473fd294940c2ba37779acfdc19c901f", null ],
      [ "YAWT_Q_FRAME_MAX_STREAM_DATA", "group__QUIC.html#gga57a79159b86da14e34eb450d26fe6072abe09200a7a144c9a4fd2f58890156fd9", null ],
      [ "YAWT_Q_FRAME_MAX_STREAMS_BIDI", "group__QUIC.html#gga57a79159b86da14e34eb450d26fe6072af62ae1932b4f120de266b4cb350583b2", null ],
      [ "YAWT_Q_FRAME_MAX_STREAMS_UNI", "group__QUIC.html#gga57a79159b86da14e34eb450d26fe6072a7c81a4520cf81eac625f374b81198bf4", null ],
      [ "YAWT_Q_FRAME_DATA_BLOCKED", "group__QUIC.html#gga57a79159b86da14e34eb450d26fe6072aa4f7973a1a372750431be257dd78a62f", null ],
      [ "YAWT_Q_FRAME_STREAM_DATA_BLOCKED", "group__QUIC.html#gga57a79159b86da14e34eb450d26fe6072af3b9d767e4ba2bdf9cf27ac4d7b4effa", null ],
      [ "YAWT_Q_FRAME_STREAMS_BLOCKED_BIDI", "group__QUIC.html#gga57a79159b86da14e34eb450d26fe6072a4cb7709e231ad47410991c2b3dcde898", null ],
      [ "YAWT_Q_FRAME_STREAMS_BLOCKED_UNI", "group__QUIC.html#gga57a79159b86da14e34eb450d26fe6072ab7e3756e39c560f1d966582fe7094dd9", null ],
      [ "YAWT_Q_FRAME_NEW_CONNECTION_ID", "group__QUIC.html#gga57a79159b86da14e34eb450d26fe6072ab11038fbe232986d87b8edfd0908b121", null ],
      [ "YAWT_Q_FRAME_RETIRE_CONNECTION_ID", "group__QUIC.html#gga57a79159b86da14e34eb450d26fe6072a1d876d9c704b1d9b053b85618ecc96a0", null ],
      [ "YAWT_Q_FRAME_PATH_CHALLENGE", "group__QUIC.html#gga57a79159b86da14e34eb450d26fe6072a32464bc6051691211b8a9dc1e6bf1ee9", null ],
      [ "YAWT_Q_FRAME_PATH_RESPONSE", "group__QUIC.html#gga57a79159b86da14e34eb450d26fe6072a7c67983842908f38299b778da308a8dc", null ],
      [ "YAWT_Q_FRAME_CONNECTION_CLOSE", "group__QUIC.html#gga57a79159b86da14e34eb450d26fe6072a3aba2fa3b1d14c1ba2fcb075db53fef7", null ],
      [ "YAWT_Q_FRAME_CONNECTION_CLOSE_APP", "group__QUIC.html#gga57a79159b86da14e34eb450d26fe6072a0b42b332f860bfe56ba97e7fc77b6a6c", null ],
      [ "YAWT_Q_FRAME_HANDSHAKE_DONE", "group__QUIC.html#gga57a79159b86da14e34eb450d26fe6072abe7d97c4778fdb4b41178bff620ef975", null ],
      [ "YAWT_Q_FRAME_DATAGRAM", "group__QUIC.html#gga57a79159b86da14e34eb450d26fe6072a8170122242330584c3fe4adaed3a9345", null ],
      [ "YAWT_Q_FRAME_DATAGRAM_LEN", "group__QUIC.html#gga57a79159b86da14e34eb450d26fe6072a859edf22d14d1449488f95067f4b084b", null ]
    ] ],
    [ "YAWT_Q_Stream_Type_t", "group__QUIC.html#ga18527349c2d3f9f52c1600abc554b8b6", [
      [ "YAWT_Q_C_BIDI", "group__QUIC.html#gga18527349c2d3f9f52c1600abc554b8b6a01460935f6680bd66743e39c5b295cd8", null ],
      [ "YAWT_Q_S_BIDI", "group__QUIC.html#gga18527349c2d3f9f52c1600abc554b8b6a4e4e288c999f86163d307d3c7289ff79", null ],
      [ "YAWT_Q_C_UNI", "group__QUIC.html#gga18527349c2d3f9f52c1600abc554b8b6a42b078386de41bd462f3722e35707421", null ],
      [ "YAWT_Q_S_UNI", "group__QUIC.html#gga18527349c2d3f9f52c1600abc554b8b6a7b862a4f7a893c0edb202fd12fea89bc", null ]
    ] ],
    [ "YAWT_Q_UserDataSlot_t", "group__QUIC.html#ga5aa8acc1e2c46e1e354ce48bb38771e7", [
      [ "YAWT_UD_APP", "group__QUIC.html#gga5aa8acc1e2c46e1e354ce48bb38771e7a0b01eb6d9d844619bcf227e1eac0609d", null ],
      [ "YAWT_UD_QUIC", "group__QUIC.html#gga5aa8acc1e2c46e1e354ce48bb38771e7a3669e542329deeb7675c1b0c63f26c93", null ],
      [ "YAWT_UD_H3", "group__QUIC.html#gga5aa8acc1e2c46e1e354ce48bb38771e7a163be659f2dea667a427b342139f9203", null ],
      [ "YAWT_UD_WT", "group__QUIC.html#gga5aa8acc1e2c46e1e354ce48bb38771e7a8d61189fb1c0b4a3280899f7e54a15f8", null ],
      [ "YAWT_UD_COUNT", "group__QUIC.html#gga5aa8acc1e2c46e1e354ce48bb38771e7acf50986e8d0e2511f7ae68c34f81879a", null ]
    ] ]
];