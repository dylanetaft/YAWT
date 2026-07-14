var group__WebTransport =
[
    [ "YAWT_WT_Session_t", "structYAWT__WT__Session__t.html", [
      [ "capsule_parser", "structYAWT__WT__Session__t.html#a9e1429e33bc728d9a569c2aefb404e92", null ],
      [ "closed", "structYAWT__WT__Session__t.html#ab0dfa87ee7065278c9214ce53cfd6f86", null ],
      [ "connect_stream_id", "structYAWT__WT__Session__t.html#ab0bd0df8dee73959fae7f3da6fc6d055", null ],
      [ "draining", "structYAWT__WT__Session__t.html#ac0901c65922974edc4e85efdfa7b1a98", null ],
      [ "in_use", "structYAWT__WT__Session__t.html#a910240753b273fc7ca5e3dab2b4bb474", null ],
      [ "max_data", "structYAWT__WT__Session__t.html#aad893d161cea39580bc5be4dcb60062a", null ],
      [ "max_streams_bidi", "structYAWT__WT__Session__t.html#a734e3049e163c1abfb8214eb10ce3c84", null ],
      [ "max_streams_uni", "structYAWT__WT__Session__t.html#aa729c401cb5c911ebd2112c56a0ae38d", null ],
      [ "open_streams_bidi", "structYAWT__WT__Session__t.html#a7c058f5dce7e3000f36628a2915935f4", null ],
      [ "open_streams_uni", "structYAWT__WT__Session__t.html#af261ba93161f7cc9054c178a14d81be8", null ],
      [ "recv_data", "structYAWT__WT__Session__t.html#a3b92f41faa231b736ee5c5257d0a3b6d", null ],
      [ "sent_data", "structYAWT__WT__Session__t.html#a35c6d8213ad81f46cb5ae1fdacd0748d", null ],
      [ "session_id", "structYAWT__WT__Session__t.html#a97b387144e1de5d06185fe610ad09b91", null ]
    ] ],
    [ "YAWT_WT_Stream_t", "structYAWT__WT__Stream__t.html", [
      [ "hdr_buffer", "structYAWT__WT__Stream__t.html#a3ebf7cff20fd8f8410cfe7c8e3168759", null ],
      [ "hdr_complete", "structYAWT__WT__Stream__t.html#ad5c3d15e1a8724538563f56a5e936583", null ],
      [ "session", "structYAWT__WT__Stream__t.html#a41645cf520a1687636a2b6a86ee64d8d", null ],
      [ "session_id", "structYAWT__WT__Stream__t.html#aea5b4f800c8d3643b405d705e7e39a35", null ],
      [ "type", "structYAWT__WT__Stream__t.html#afd3882a18fda8b01c8b495eee8e38101", null ]
    ] ],
    [ "YAWT_WT_Context_t", "structYAWT__WT__Context__t.html", [
      [ "app_handler", "structYAWT__WT__Context__t.html#a19690e2c643dc197abb4f14b4641550d", null ],
      [ "nsessions", "structYAWT__WT__Context__t.html#ae09af5554435ae5e82cfe30289765401", null ],
      [ "qcon", "structYAWT__WT__Context__t.html#ad9facfb2decc4c536aca0411a218b2e6", null ],
      [ "sessions", "structYAWT__WT__Context__t.html#a8861ff6074b30022e3771e168e31ded6", null ]
    ] ],
    [ "YAWT_WT_CapsuleCloseSession_t", "structYAWT__WT__CapsuleCloseSession__t.html", [
      [ "app_error_code", "structYAWT__WT__CapsuleCloseSession__t.html#a7dc0556330e181ffe2f6221addd68124", null ],
      [ "app_error_message", "structYAWT__WT__CapsuleCloseSession__t.html#a7fc653be0e9b3767651838ddca45ecdb", null ],
      [ "message_len", "structYAWT__WT__CapsuleCloseSession__t.html#a81d63da2e1634b71764163ffabdba487", null ]
    ] ],
    [ "YAWT_WT_CapsuleDrainSession_t", "structYAWT__WT__CapsuleDrainSession__t.html", null ],
    [ "YAWT_WT_CapsuleMaxStreams_t", "structYAWT__WT__CapsuleMaxStreams__t.html", [
      [ "is_bidi", "structYAWT__WT__CapsuleMaxStreams__t.html#a6e483774026c4b2a545f073d5a913b25", null ],
      [ "maximum_streams", "structYAWT__WT__CapsuleMaxStreams__t.html#abc922965f536071505c6f649dcebb147", null ]
    ] ],
    [ "YAWT_WT_CapsuleStreamsBlocked_t", "structYAWT__WT__CapsuleStreamsBlocked__t.html", [
      [ "is_bidi", "structYAWT__WT__CapsuleStreamsBlocked__t.html#a73011fb415a69f3f03012bc0339efa79", null ],
      [ "maximum_streams", "structYAWT__WT__CapsuleStreamsBlocked__t.html#a1a4662025a0198a9aa40d9fb1a6f0e60", null ]
    ] ],
    [ "YAWT_WT_CapsuleMaxData_t", "structYAWT__WT__CapsuleMaxData__t.html", [
      [ "maximum_data", "structYAWT__WT__CapsuleMaxData__t.html#aa1d5ac7f3be13a576f92f365808fe554", null ]
    ] ],
    [ "YAWT_WT_CapsuleDataBlocked_t", "structYAWT__WT__CapsuleDataBlocked__t.html", [
      [ "maximum_data", "structYAWT__WT__CapsuleDataBlocked__t.html#abf6e0c2d72156d4662890f9b542764c2", null ]
    ] ],
    [ "YAWT_WT_CapsuleDatagram_t", "structYAWT__WT__CapsuleDatagram__t.html", [
      [ "payload", "structYAWT__WT__CapsuleDatagram__t.html#ae444e57b4c7a1ae5efd9a340b212a617", null ],
      [ "payload_len", "structYAWT__WT__CapsuleDatagram__t.html#afb05938f718dae59250323a6eedf4524", null ]
    ] ],
    [ "YAWT_WT_Capsule_t", "unionYAWT__WT__Capsule__t.html", [
      [ "close_session", "unionYAWT__WT__Capsule__t.html#a881cb8dd8fa16f2cb0fc0b7c4ed6ed34", null ],
      [ "data_blocked", "unionYAWT__WT__Capsule__t.html#ace9994790d84074be0f5c45824352614", null ],
      [ "datagram", "unionYAWT__WT__Capsule__t.html#a12638f4534fd02ee53b047665877a21c", null ],
      [ "drain_session", "unionYAWT__WT__Capsule__t.html#a811cb2cecbe03bc61d1a9d6f7751e416", null ],
      [ "max_data", "unionYAWT__WT__Capsule__t.html#a6284450576c8a1d7d7092b342ca9d31a", null ],
      [ "max_streams", "unionYAWT__WT__Capsule__t.html#a2b57b4b50029f3c155ce9707b4acdc2f", null ],
      [ "streams_blocked", "unionYAWT__WT__Capsule__t.html#a0a842aa9dd20b45242d6f91339854f78", null ]
    ] ],
    [ "YAWT_WT_EventParam", "unionYAWT__WT__EventParam.html", [
      [ "capsule", "unionYAWT__WT__EventParam.html#a035fa69dd5014f5ff74eaa55adddd351", null ],
      [ "data", "unionYAWT__WT__EventParam.html#a1195dccbcc521824f40640339248ceff", null ],
      [ "fin", "unionYAWT__WT__EventParam.html#afc48a4c36f8b1139c2c2b45785571f2f", null ],
      [ "len", "unionYAWT__WT__EventParam.html#a8d33ec1691667421c79092d397fc2403", null ],
      [ "P_EVT_CAPSULE_RECEIVED", "unionYAWT__WT__EventParam.html#adb87486f5bd90c610bdaaa9804063d23", null ],
      [ "P_EVT_DATAGRAM", "unionYAWT__WT__EventParam.html#adff2452dc17b0b7f130c4674561846d3", null ],
      [ "P_EVT_SESSION_ESTABLISHED", "unionYAWT__WT__EventParam.html#a587306f98c9296dba063c5da90072aa2", null ],
      [ "P_EVT_STREAM_DATA", "unionYAWT__WT__EventParam.html#ad254eaf93649f86b92524343c97552f2", null ],
      [ "session_id", "unionYAWT__WT__EventParam.html#a9f0ee329e1b6d12f7f2b06b4f90c5ada", null ],
      [ "stream_id", "unionYAWT__WT__EventParam.html#ad8ab1b43bba5c620827a98d516778dea", null ],
      [ "type", "unionYAWT__WT__EventParam.html#af0d24d2851f9384487bdce895938617c", null ]
    ] ],
    [ "YAWT_WT_ERR_APP_RANGE_FIRST", "group__WebTransport.html#gafe26b74f149f2029ca92da18fbcca823", null ],
    [ "YAWT_WT_ERR_APP_RANGE_LAST", "group__WebTransport.html#gacd7caa447fb3a10023f57967393f7577", null ],
    [ "YAWT_WT_EventHandler_t", "group__WebTransport.html#ga81e8ff3c50ad95023d50279e9b23604c", null ],
    [ "YAWT_WT_EventParam_t", "group__WebTransport.html#ga04a35a3639538c93dcd2ef75f55c118d", null ],
    [ "YAWT_WT_CapsuleType_t", "group__WebTransport.html#ga6c845ee614d05a1e7cf70eb2d1a78901", [
      [ "YAWT_WT_CAPSULE_DATAGRAM", "group__WebTransport.html#gga6c845ee614d05a1e7cf70eb2d1a78901a029b5d2758f1e5d0b32e2a0d85c500ee", null ],
      [ "YAWT_WT_CAPSULE_CLOSE_SESSION", "group__WebTransport.html#gga6c845ee614d05a1e7cf70eb2d1a78901a839b0623002bc33f1f84d45aa557287d", null ],
      [ "YAWT_WT_CAPSULE_DRAIN_SESSION", "group__WebTransport.html#gga6c845ee614d05a1e7cf70eb2d1a78901aa54ec8716a4a8b3ee0a3321d0cefc898", null ],
      [ "YAWT_WT_CAPSULE_MAX_DATA", "group__WebTransport.html#gga6c845ee614d05a1e7cf70eb2d1a78901abc932af23f75dd9227f97d25c8277f86", null ],
      [ "YAWT_WT_CAPSULE_MAX_STREAMS_BIDI", "group__WebTransport.html#gga6c845ee614d05a1e7cf70eb2d1a78901a27969679925516744d82b7d05035a8da", null ],
      [ "YAWT_WT_CAPSULE_MAX_STREAMS_UNI", "group__WebTransport.html#gga6c845ee614d05a1e7cf70eb2d1a78901aa03294bfe46d13554732fea621fb9b97", null ],
      [ "YAWT_WT_CAPSULE_DATA_BLOCKED", "group__WebTransport.html#gga6c845ee614d05a1e7cf70eb2d1a78901a795e65de90708ed63e85b7353203501d", null ],
      [ "YAWT_WT_CAPSULE_STREAMS_BLOCKED_BIDI", "group__WebTransport.html#gga6c845ee614d05a1e7cf70eb2d1a78901a36b2cf7f7aae72f8d5c273c3d40841e5", null ],
      [ "YAWT_WT_CAPSULE_STREAMS_BLOCKED_UNI", "group__WebTransport.html#gga6c845ee614d05a1e7cf70eb2d1a78901ac4f917105651284246444478c5885a86", null ]
    ] ],
    [ "YAWT_WT_Error_t", "group__WebTransport.html#gacaadeff44bd0a37e0f09a3d7d7e4f5df", [
      [ "YAWT_WT_OK", "group__WebTransport.html#ggacaadeff44bd0a37e0f09a3d7d7e4f5dfafff322fa1ac02e983e9de0d84d727cdc", null ],
      [ "YAWT_WT_ERR_SHORT_BUFFER", "group__WebTransport.html#ggacaadeff44bd0a37e0f09a3d7d7e4f5dfaab7cf3eaba9761920781cea4599d9afb", null ],
      [ "YAWT_WT_ERR_INCOMPLETE", "group__WebTransport.html#ggacaadeff44bd0a37e0f09a3d7d7e4f5dfa7c0f12e7c38d60b32f5065e4b0c9c650", null ],
      [ "YAWT_WT_ERR_MALFORMED", "group__WebTransport.html#ggacaadeff44bd0a37e0f09a3d7d7e4f5dfa059bf21c36ab56eece1fdc3de516f211", null ],
      [ "YAWT_WT_ERR_INVALID_PARAM", "group__WebTransport.html#ggacaadeff44bd0a37e0f09a3d7d7e4f5dfa3eb58cf2d024ee2f62543c5306a2ca5a", null ],
      [ "YAWT_WT_ERR_NO_APP_HANDLER", "group__WebTransport.html#ggacaadeff44bd0a37e0f09a3d7d7e4f5dfab269632199c02b0a1045c60781c7f16c", null ],
      [ "YAWT_WT_ERR_NO_SESSION", "group__WebTransport.html#ggacaadeff44bd0a37e0f09a3d7d7e4f5dfa9cb1d85f537ac45ad84dda5236a4e1d3", null ],
      [ "YAWT_WT_ERR_FLOW_CONTROL", "group__WebTransport.html#ggacaadeff44bd0a37e0f09a3d7d7e4f5dfafb5347a08bea888aad1dbe484ac1cbd5", null ],
      [ "YAWT_WT_ERR_SESSION_CLOSED", "group__WebTransport.html#ggacaadeff44bd0a37e0f09a3d7d7e4f5dfa46884a7cf2a26c971f374b9226d89090", null ]
    ] ],
    [ "YAWT_WT_ErrorCode_t", "group__WebTransport.html#gab3b35ae694fa211b8456671f1a43e7ec", [
      [ "YAWT_WT_ERR_BUFFERED_STREAM_REJECTED", "group__WebTransport.html#ggab3b35ae694fa211b8456671f1a43e7ecade20857678029869d556ba6cf265de0f", null ],
      [ "YAWT_WT_ERR_SESSION_GONE", "group__WebTransport.html#ggab3b35ae694fa211b8456671f1a43e7eca56cb65d53ac716593e5eec64c8f4a79b", null ],
      [ "YAWT_WT_ERR_FLOW_CONTROL_ERROR", "group__WebTransport.html#ggab3b35ae694fa211b8456671f1a43e7eca36226b3320e9011152beea39483f1502", null ],
      [ "YAWT_WT_ERR_ALPN_ERROR", "group__WebTransport.html#ggab3b35ae694fa211b8456671f1a43e7eca7401c49e765848c28cf5e9a4b278a797", null ],
      [ "YAWT_WT_ERR_REQUIREMENTS_NOT_MET", "group__WebTransport.html#ggab3b35ae694fa211b8456671f1a43e7eca13814cb68508ff77c9d5087f913d7b1f", null ]
    ] ],
    [ "YAWT_WT_EventType_t", "group__WebTransport.html#ga28bec1ca9365cffe1b441f02e15c8b79", [
      [ "YAWT_WT_EVT_SESSION_ESTABLISHED", "group__WebTransport.html#gga28bec1ca9365cffe1b441f02e15c8b79aa6ea2f404aa6bcbfd76cc6f0a2bea8be", null ],
      [ "YAWT_WT_EVT_STREAM_DATA", "group__WebTransport.html#gga28bec1ca9365cffe1b441f02e15c8b79a0fdd078359b5a248a07a6d56274765c7", null ],
      [ "YAWT_WT_EVT_DATAGRAM", "group__WebTransport.html#gga28bec1ca9365cffe1b441f02e15c8b79a55fa865fe45351ae6baa9632faca2383", null ],
      [ "YAWT_WT_EVT_CAPSULE_RECEIVED", "group__WebTransport.html#gga28bec1ca9365cffe1b441f02e15c8b79ae562f26fb5a8f0e99cea008499e9d55e", null ]
    ] ],
    [ "YAWT_WT_StreamDir_t", "group__WebTransport.html#gaeea4e7b5b9891eff17190d24739a23c1", [
      [ "YAWT_WT_DIR_UNI", "group__WebTransport.html#ggaeea4e7b5b9891eff17190d24739a23c1a0fef18fb7182309eb3943d2976929b98", null ],
      [ "YAWT_WT_DIR_BIDI", "group__WebTransport.html#ggaeea4e7b5b9891eff17190d24739a23c1a79f2bdb7f8cdaff4de7352aecc256d46", null ]
    ] ],
    [ "YAWT_wt_err_str", "group__WebTransport.html#gae16fdacaf0a5c0e61753d1bbffa0ddec", null ],
    [ "YAWT_wt_on_datagram", "group__WebTransport.html#ga6747a0b186a9cca16605a8a33d8924b5", null ],
    [ "YAWT_wt_on_event", "group__WebTransport.html#ga9b60cce42823a0f222aece4940e7df31", null ],
    [ "YAWT_wt_on_h3_event", "group__WebTransport.html#ga55827ec0b36e71737a30044b697aa1b7", null ],
    [ "YAWT_wt_open_stream", "group__WebTransport.html#ga47927bb69db86806d615b611d6f42836", null ],
    [ "YAWT_wt_parse_capsule", "group__WebTransport.html#ga87c798b1cde2366b4fa235e48bcbdced", null ],
    [ "YAWT_wt_receive_capsule", "group__WebTransport.html#gaecb6ae132f404f7c4d55962a477b6ce0", null ],
    [ "YAWT_wt_send_capsule", "group__WebTransport.html#ga8289c8b0fb94752bde87ac0e6f7e90de", null ],
    [ "YAWT_wt_send_data", "group__WebTransport.html#ga38221baabd2aa94beb5f2ff44ac84000", null ],
    [ "YAWT_wt_send_datagram", "group__WebTransport.html#gacbab03a207bf9ac670d3189f0e52bcb5", null ],
    [ "YAWT_wt_set_event_handler", "group__WebTransport.html#gad99513267e7d8400e7fc9fc74433decc", null ]
];