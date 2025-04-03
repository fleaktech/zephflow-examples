package io.fleak.zephflowexamples;

import io.fleak.zephflow.lib.parser.ParserConfigs;
import io.fleak.zephflow.lib.parser.extractions.GrokExtractionConfig;
import io.fleak.zephflow.lib.parser.extractions.SyslogExtractionConfig;
import io.fleak.zephflow.lib.parser.extractions.SyslogExtractionRule;
import io.fleak.zephflow.lib.serdes.EncodingType;
import io.fleak.zephflow.lib.utils.MiscUtils;
import io.fleak.zephflow.sdk.ZephFlow;
import java.io.File;
import java.net.URL;
import java.util.List;
import java.util.Objects;

/** Created by bolei on 3/31/25 */
public class Main {
  public static void main(String[] args) throws Exception {
    ClassLoader classLoader = Main.class.getClassLoader();
    URL resourceUrl = classLoader.getResource("cisco_asa_data.txt");
    File file = new File(Objects.requireNonNull(resourceUrl).getFile());
    String absolutePath = file.getAbsolutePath();

    ZephFlow flow = ZephFlow.startFlow();
    var inputFlow = flow.fileSource(absolutePath, EncodingType.STRING_LINE);

    var syslogHeaderParsedFlow =
        inputFlow.parse(
            ParserConfigs.ParserConfig.builder()
                .targetField(MiscUtils.FIELD_NAME_RAW)
                .extractionConfig(
                    SyslogExtractionConfig.builder()
                        .componentList(
                            List.of(
                                SyslogExtractionConfig.ComponentType.TIMESTAMP,
                                SyslogExtractionConfig.ComponentType.DEVICE,
                                SyslogExtractionConfig.ComponentType.APP))
                        .messageBodyDelimiter(':')
                        .timestampPattern("MMM dd yyyy HH:mm:ss")
                        .build())
                .build());
    var asaHeaderParsedFlow =
        syslogHeaderParsedFlow.parse(
            ParserConfigs.ParserConfig.builder()
                .targetField(SyslogExtractionRule.LOG_CONTENT_KEY)
                .removeTargetField(true)
                .extractionConfig(
                    GrokExtractionConfig.builder()
                        .grokExpression(
                            "%ASA-%{INT:level}-%{INT:message_number}: %{GREEDYDATA:message_text}")
                        .build())
                .build());
    var msg106023Flow =
        asaHeaderParsedFlow
            .filter("$.message_number=='106023'")
            .parse(
                ParserConfigs.ParserConfig.builder()
                    .targetField("message_text")
                    .extractionConfig(
                        GrokExtractionConfig.builder()
                            .grokExpression(
                                "Deny %{WORD:protocol} src %{WORD:source_interface}:%{IP:source_ip}/%{NUMBER:source_port} dst %{WORD:dest_interface}:%{IP:dest_ip}/%{NUMBER:dest_port} by access-group %{DATA:access_group} \\[%{DATA:rule_ids}\\]")
                            .build())
                    .build())
            .eval(
"""
dict(
  url=dict(
    port=$.source_port,
    scheme='http',
    hostname=$.source_ip
  ),
  time=ts_str_to_epoch($.timestamp, 'MMM dd yyyy HH:mm:ss'),
  proxy=dict(
    ip=$.source_ip,
    port=$.source_port,
    type='Server',
    type_id=1
  ),
  status=case(
    str_contains($.message_text, 'Deny') => 'Failure',
    _ => 'Success'
  ),
  message=$.message_text,
  metadata=dict(
    product=dict(
      name='Cisco ASA',
      vendor_name='Cisco'
    ),
    version="1.4.0",
    log_name='ASA',
    log_level=case(
      $.level == '4' => 'Warning',
      _ => to_str($.level)
    ),
    event_code=$.message_number,
    log_provider=$.appName
  ),
  type_uid=400104,
  class_uid=4001,
  status_id=case(
    str_contains($.message_text, 'Deny') => 2,
    _ => 1
  ),
  activity_id=99,
  severity_id=case(
    $.level == '4' => 3,
    _ => 0
  ),
  status_code=$.rule_ids,
  category_uid=4,
  dst_endpoint=dict(
    ip=$.dest_ip,
    port=$.dest_port,
    type_id=1,
    interface_name=$.dest_interface
  ),
  src_endpoint=dict(
    ip=$.source_ip,
    port=$.source_port,
    type_id=1,
    interface_name=$.source_interface
  ),
  status_detail=case(
    str_contains($.message_text, 'Deny') and str_contains($.message_text, 'by access-group') => 'Denied by access-group ' + $.access_group,
    str_contains($.message_text, 'Deny') => 'Denied traffic',
    _ => null
  ),
  connection_info=dict(
    boundary=case(
      $.source_interface == 'outside' or $.dest_interface == 'outside' => 'External',
      _ => 'Internal'
    ),
    direction=case(
      $.source_interface == 'outside' and $.dest_interface == 'inside' => 'Inbound',
      $.source_interface == 'inside' and $.dest_interface == 'outside' => 'Outbound',
      _ => 'Lateral'
    ),
    boundary_id=case(
      $.source_interface == 'outside' or $.dest_interface == 'outside' => 3,
      _ => 2
    ),
    direction_id=case(
      $.source_interface == 'outside' and $.dest_interface == 'inside' => 1,
      $.source_interface == 'inside' and $.dest_interface == 'outside' => 2,
      _ => 3
    ),
    protocol_name=$.protocol
  ),
  timezone_offset=0
)
""");
    var msg302013Flow =
        asaHeaderParsedFlow
            .filter("$.message_number=='302013'")
            .parse(
                ParserConfigs.ParserConfig.builder()
                    .targetField("message_text")
                    .extractionConfig(
                        GrokExtractionConfig.builder()
                            .grokExpression(
                                "%{WORD:action} %{WORD:direction} %{WORD:protocol} connection %{NUMBER:connection_id} for %{WORD:source_interface}:%{IP:source_ip}/%{NUMBER:source_port} \\(%{IP:source_mapped_ip}/%{NUMBER:source_mapped_port}\\) to %{WORD:dest_interface}:%{IP:dest_ip}/%{NUMBER:dest_port} \\(%{IP:dest_mapped_ip}/%{NUMBER:dest_mapped_port}\\)")
                            .build())
                    .build())
            .eval(
"""
dict(
  url=dict(
    port=$.source_port,
    domain=$.source_ip,
    scheme='http',
    hostname=$.source_ip
  ),
  time=ts_str_to_epoch($.timestamp, 'MMM dd yyyy HH:mm:ss'),
  proxy=dict(
    ip=$.source_ip,
    port=$.source_port,
    type='proxy',
    type_id=1,
    hostname=$.deviceId,
    interface_name=$.source_interface
  ),
  status=case(
    $.action == 'Built' => 'Success',
    _ => 'Unknown'
  ),
  message=$.message_text,
  metadata=dict(
    product=dict(
      name='Cisco ASA',
      vendor_name='Cisco'
    ),
    version="1.4.0",
    log_name='ASA',
    event_code=$.message_number,
    log_provider=$.appName,
    original_time=$.timestamp
  ),
  type_uid=4001 * 100 + 1,
  class_uid=4001,
  status_id=case(
    $.action == 'Built' => 1,
    _ => 0
  ),
  activity_id=1,
  severity_id=case(
    $.level == '6' => 1,
    _ => 0
  ),
  status_code=$.level,
  category_uid=4,
  dst_endpoint=dict(
    ip=$.dest_ip,
    port=$.dest_port,
    domain=$.dest_interface,
    hostname=$.deviceId
  ),
  src_endpoint=dict(
    ip=$.source_ip,
    port=$.source_port,
    type_id=1,
    interface_name=$.source_interface
  ),
  status_detail=case(
    $.action == 'Built' => 'TCP connection ' + $.connection_id + ' built from ' + $.source_interface + ':' + $.source_ip + '/' + $.source_port + ' to ' + $.dest_interface + ':' + $.dest_ip + '/' + $.dest_port,
    _ => null
  ),
  connection_info=dict(
    uid=$.connection_id,
    direction=$.direction,
    direction_id=case(
      $.direction == 'outbound' => 2,
      $.direction == 'inbound' => 1,
      _ => 0
    ),
    protocol_name=lower($.protocol)
  ),
  timezone_offset=0
)
""");
    var msg302014Flow =
        asaHeaderParsedFlow
            .filter("$.message_number=='302014'")
            .parse(
                ParserConfigs.ParserConfig.builder()
                    .targetField("message_text")
                    .extractionConfig(
                        GrokExtractionConfig.builder()
                            .grokExpression(
                                "Teardown %{WORD:protocol} connection %{NUMBER:connection_id} for %{WORD:source_interface}:%{IP:source_ip}/%{NUMBER:source_port} to %{WORD:dest_interface}:%{IP:dest_ip}/%{NUMBER:dest_port} duration %{TIME:duration} bytes %{NUMBER:bytes} %{GREEDYDATA:reason}")
                            .build())
                    .build())
            .eval(
"""
dict(
  url=dict(
    port=$.source_port,
    scheme="http",
    hostname=$.source_ip,
    url_string="http://" + $.source_ip + ":" + $.source_port
  ),
  time=ts_str_to_epoch($.timestamp, 'MMM dd yyyy HH:mm:ss'),
  proxy=dict(
    ip=$.source_ip,
    port=$.source_port,
    type="Server",
    type_id=1
  ),
  status=case(
    str_contains($.reason, 'Reset-I') => 'Reset from Inside',
    str_contains($.reason, 'Reset-O') => 'Reset from Outside',
    str_contains($.message_text, 'Teardown') => 'Teardown',
    _ => $.reason
  ),
  message=$.message_text,
  traffic=dict(
    bytes=parse_int($.bytes)
  ),
  metadata=dict(
    uid=$.connection_id,
    product=dict(
      name="Cisco ASA",
      vendor_name="Cisco"
    ),
    version="1.4.0",
    log_name=$.appName,
    event_code="302014",
    logged_time=ts_str_to_epoch($.timestamp, 'MMM dd yyyy HH:mm:ss'),
    log_provider="CiscoASA",
    original_time=$.timestamp
  ),
  type_uid=400100 + case(
        str_contains($.reason, 'Reset') => 3,
        str_contains($.message_text, 'Teardown') => 2,
        _ => 99
    ),
  class_uid=4001,
  status_id=case(
    str_contains($.reason, 'Reset') => 2,
    str_contains($.message_text, 'Teardown') => 1,
    _ => 99
  ),
  activity_id=case(
    str_contains($.reason, 'Reset') => 3,
    str_contains($.message_text, 'Teardown') => 2,
    _ => 99
  ),
  severity_id=case(
    $.level == '6' => 1,
    _ => 0
  ),
  status_code=$.reason,
  category_uid=4,
  dst_endpoint=dict(
    ip=$.dest_ip,
    port=$.dest_port,
    type_id=1,
    interface_name=$.dest_interface
  ),
  src_endpoint=dict(
    ip=$.source_ip,
    port=$.source_port,
    type_id=1,
    interface_name=$.source_interface
  ),
  status_detail=case(
    str_contains($.reason, 'TCP Reset-I') => 'Connection reset initiated from inside network',
    str_contains($.reason, 'TCP Reset-O') => 'Connection reset initiated from outside network',
    str_contains($.message_text, 'Teardown') => 'Connection teardown with reason: ' + $.reason,
    _ => $.reason
  ),
  connection_info=dict(
    uid=$.connection_id,
    boundary=case(
      $.source_interface == $.dest_interface => 'Localhost',
      _ => 'Internal'
    ),
    direction=case(
      $.source_interface == 'outside' and $.dest_interface == 'inside' => 'Inbound',
      $.source_interface == 'inside' and $.dest_interface == 'outside' => 'Outbound',
      _ => 'Lateral'
    ),
    boundary_id=case(
      $.source_interface == $.dest_interface => 1,
      _ => 2
    ),
    direction_id=case(
      $.source_interface == 'outside' and $.dest_interface == 'inside' => 1,
      $.source_interface == 'inside' and $.dest_interface == 'outside' => 2,
      _ => 3
    ),
    protocol_name=lower($.protocol)
  ),
  timezone_offset=0
)
""");
    var msg302015Flow =
        asaHeaderParsedFlow
            .filter("$.message_number=='302015'")
            .parse(
                ParserConfigs.ParserConfig.builder()
                    .targetField("message_text")
                    .extractionConfig(
                        GrokExtractionConfig.builder()
                            .grokExpression(
                                "Built %{WORD:direction} %{WORD:protocol} connection %{NUMBER:connection_id} for %{WORD:source_interface}:%{IP:source_ip}/%{NUMBER:source_port} \\(%{IP:source_mapped_ip}/%{NUMBER:source_mapped_port}\\) to %{WORD:dest_interface}:%{IP:dest_ip}/%{NUMBER:dest_port} \\(%{IP:dest_mapped_ip}/%{NUMBER:dest_mapped_port}\\)")
                            .build())
                    .build())
            .eval(
"""
dict(
  url=dict(
    port=case(
      $.source_interface == 'outside' => parse_int($.source_port),
      _ => null
    ),
    scheme='dns',
    hostname=case(
      $.source_interface == 'outside' => $.source_ip,
      _ => null
    )
  ),
  time=ts_str_to_epoch($.timestamp, 'MMM dd yyyy HH:mm:ss'),
  proxy=dict(
    ip=$.source_ip,
    port=parse_int($.source_port),
    type=case(
      $.source_interface == 'outside' => 'Server',
      _ => 'Unknown'
    ),
    domain=$.source_interface,
    type_id=case(
      $.source_interface == 'outside' => 1,
      _ => 0
    ),
    hostname=$.source_ip
  ),
  status=case(
    $.message_number == '302015' => 'Success',
    _ => null
  ),
  message=$.message_text,
  traffic=dict(
    bytes=null,
    packets=null,
    bytes_in=null,
    bytes_out=null,
    packets_in=null,
    packets_out=null
  ),
  metadata=dict(
    product=dict(
      name='Cisco ASA',
      vendor_name='Cisco'
    ),
    version="1.4.0",
    log_name='ASA',
    log_level=$.level,
    event_code=$.message_number,
    log_provider=$.appName,
    original_time=$.timestamp
  ),
  type_uid=400101,
  class_uid=4001,
  status_id=case(
    $.message_number == '302015' => 1,
    _ => 0
  ),
  activity_id=1,
  severity_id=1,
  status_code=$.message_number,
  category_uid=4,
  dst_endpoint=dict(
    ip=$.dest_ip,
    port=$.dest_port,
    domain=$.dest_interface,
    hostname=$.deviceId
  ),
  src_endpoint=dict(
    ip=$.source_ip,
    port=$.source_port,
    domain=$.source_interface,
    type_id=case(
      $.source_interface == 'outside' => 1,
      _ => 0
    ),
    hostname=case(
      $.source_interface == 'outside' => $.source_ip,
      _ => null
    )
  ),
  status_detail=case(
    $.message_number == '302015' => 'Built ' + $.direction + ' UDP connection ' + $.connection_id + ' for ' + $.source_interface + ':' + $.source_ip + '/' + $.source_port + ' to ' + $.dest_interface + ':' + $.dest_ip + '/' + $.dest_port,
    _ => null
  ),
  connection_info=dict(
    uid=$.connection_id,
    boundary='External',
    direction=$.direction,
    boundary_id=3,
    direction_id=case(
      $.direction == 'outbound' => 2,
      $.direction == 'inbound' => 1,
      _ => 0
    ),
    protocol_name=lower($.protocol),
    protocol_ver_id=4
  ),
  timezone_offset=0
)
""");
    var msg302016Flow =
        asaHeaderParsedFlow
            .filter("$.message_number=='302016'")
            .parse(
                ParserConfigs.ParserConfig.builder()
                    .targetField("message_text")
                    .extractionConfig(
                        GrokExtractionConfig.builder()
                            .grokExpression(
                                "Teardown %{WORD:protocol} connection %{NUMBER:connection_id} for %{DATA:source_interface}:%{IP:source_ip}/%{NUMBER:source_port} to %{DATA:dest_interface}:%{IPORHOST:dest_ip}/%{NUMBER:dest_port} duration %{TIME:duration} bytes %{NUMBER:bytes}")
                            .build())
                    .build())
            .eval(
"""
dict(
  url=dict(
    port=case(
      $.source_interface == 'outside' => $.source_port,
      _ => null
    ),
    domain=case(
      $.source_interface == 'outside' => $.source_interface,
      _ => null
    ),
    hostname=case(
      $.source_interface == 'outside' => $.source_ip,
      _ => null
    )
  ),
  time=ts_str_to_epoch($.timestamp, 'MMM dd yyyy HH:mm:ss'),
  proxy=dict(
    ip=$.source_ip,
    port=$.source_port,
    type=case(
      $.source_interface == 'outside' => 'Server',
      _ => 'Unknown'
    ),
    domain=$.source_interface,
    type_id=case(
      $.source_interface == 'outside' => 1,
      _ => 0
    )
  ),
  status=case(
    $.message_number == '302016' => 'Teardown',
    _ => null
  ),
  message=$.message_text,
  traffic=dict(
    bytes=parse_int($.bytes)
  ),
  metadata=dict(
    product=dict(
      name='CiscoASA',
      vendor_name='Cisco'
    ),
    version="1.4.0",
    log_name='ASA',
    log_level=case(
      $.level == '6' => 'Informational',
      _ => to_str($.level)
    ),
    event_code=$.message_number,
    logged_time=ts_str_to_epoch($.timestamp, 'MMM dd yyyy HH:mm:ss')
  ),
  type_uid=400102,
  class_uid=4001,
  status_id=case(
    $.message_number == '302016' => 1,
    _ => 0
  ),
  activity_id=2,
  severity_id=1,
  status_code=$.message_number,
  category_uid=4,
  dst_endpoint=dict(
    ip=$.dest_ip,
    port=$.dest_port,
    domain=$.dest_interface
  ),
  src_endpoint=dict(
    ip=$.source_ip,
    port=$.source_port,
    domain=$.source_interface,
    type_id=case(
      $.source_interface == 'outside' => 99,
      _ => 0
    )
  ),
  status_detail=$.duration,
  connection_info=dict(
    uid=$.connection_id,
    boundary=case(
      $.source_interface == 'outside' or $.dest_interface == 'outside' => 'External',
      _ => 'Internal'
    ),
    direction=case(
      $.source_interface == 'outside' and $.dest_interface == 'inside' => 'Inbound',
      $.source_interface == 'inside' and $.dest_interface == 'outside' => 'Outbound',
      _ => 'Lateral'
    ),
    boundary_id=case(
      $.source_interface == 'outside' or $.dest_interface == 'outside' => 3,
      _ => 2
    ),
    direction_id=case(
      $.source_interface == 'outside' and $.dest_interface == 'inside' => 1,
      $.source_interface == 'inside' and $.dest_interface == 'outside' => 2,
      _ => 3
    ),
    protocol_name=lower($.protocol)
  ),
  timezone_offset=0
)
""");
    var msg305011Flow =
        asaHeaderParsedFlow
            .filter("$.message_number=='305011'")
            .parse(
                ParserConfigs.ParserConfig.builder()
                    .targetField("message_text")
                    .extractionConfig(
                        GrokExtractionConfig.builder()
                            .grokExpression(
                                "%{WORD:action} %{WORD:translation_type} %{WORD:protocol} translation from %{WORD:source_interface}:%{IP:source_ip}/%{INT:source_port} to %{WORD:dest_interface}:%{IP:dest_ip}/%{INT:dest_port}")
                            .build())
                    .build())
            .eval(
"""
dict(
  url=dict(
    port=case(
      $.dest_interface == 'outside' => parse_int($.dest_port),
      _ => null
    ),
    scheme=case(
      $.protocol == 'TCP' => 'tcp',
      _ => lower($.protocol)
    ),
    hostname=case(
      $.dest_interface == 'outside' => $.dest_ip,
      _ => null
    )
  ),
  time=ts_str_to_epoch($.timestamp, 'MMM dd yyyy HH:mm:ss'),
  proxy=dict(
    ip=$.dest_ip,
    port=parse_int($.dest_port),
    type='Server',
    type_id=1,
    interface_name=$.dest_interface
  ),
  status=case(
    $.action == 'Built' => 'Success',
    _ => null
  ),
  message=$.message_text,
  metadata=dict(
    product=dict(
      name='CiscoASA',
      vendor_name='Cisco'
    ),
    version="1.4.0",
    log_name='ASA',
    log_level=$.level,
    event_code=$.message_number,
    logged_time=ts_str_to_epoch($.timestamp, 'MMM dd yyyy HH:mm:ss')
  ),
  type_uid=4001001,
  class_uid=4001,
  status_id=case(
    $.action == 'Built' => 1,
    _ => 0
  ),
  activity_id=1,
  severity_id=case(
    $.level == '6' => 1,
    _ => 0
  ),
  status_code=$.message_number,
  category_uid=4,
  dst_endpoint=dict(
    ip=$.dest_ip,
    port=$.dest_port,
    type_id=1,
    interface_name=$.dest_interface
  ),
  src_endpoint=dict(
    ip=$.source_ip,
    port=$.source_port,
    type_id=1,
    interface_name=$.source_interface
  ),
  status_detail=$.message_text,
  connection_info=dict(
    boundary='External',
    direction='Outbound',
    boundary_id=3,
    direction_id=2,
    protocol_num=case(
      lower($.protocol) == 'tcp' => 6,
      lower($.protocol) == 'udp' => 17,
      lower($.protocol) == 'icmp' => 1,
      _ => null
    ),
    protocol_name=lower($.protocol)
  )
)
""");
    var msg305012Flow =
        asaHeaderParsedFlow
            .filter("$.message_number=='305012'")
            .parse(
                ParserConfigs.ParserConfig.builder()
                    .targetField("message_text")
                    .extractionConfig(
                        GrokExtractionConfig.builder()
                            .grokExpression(
                                "Teardown %{WORD:translation_type} %{WORD:protocol} translation from %{WORD:source_interface}:%{IP:source_ip}/%{NUMBER:source_port} to %{WORD:dest_interface}:%{IP:dest_ip}/%{NUMBER:dest_port} duration %{TIME:duration}")
                            .build())
                    .build())
            .eval(
"""
dict(
  url=dict(
    port=case(
      $.dest_port != null => parse_int($.dest_port),
      _ => null
    ),
    scheme="tcp",
    hostname=case(
      $.dest_ip != null => $.dest_ip,
      _ => null
    )
  ),
  time=ts_str_to_epoch($.timestamp, "MMM dd yyyy HH:mm:ss"),
  proxy=dict(
    ip=$.dest_ip,
    port=parse_int($.dest_port),
    type="proxy",
    type_id=99
  ),
  status="Teardown",
  message=$.message_text,
  traffic=dict(
    bytes=null,
    bytes_in=null,
    bytes_out=null
  ),
  metadata=dict(
    product=dict(
      name="Cisco ASA",
      vendor_name="Cisco"
    ),
    version="1.4.0",
    log_level="6",
    event_code=$.message_number,
    logged_time=ts_str_to_epoch($.timestamp, "MMM dd yyyy HH:mm:ss"),
    log_provider="CiscoASA"
  ),
  type_uid=4001 * 100 + 2,
  class_uid=4001,
  status_id=1,
  activity_id=2,
  severity_id=1,
  status_code=$.message_number,
  category_uid=4,
  dst_endpoint=dict(
    ip=$.dest_ip,
    port=$.dest_port,
    interface_name=$.dest_interface
  ),
  src_endpoint=dict(
    ip=$.source_ip,
    port=$.source_port,
    type="unknown",
    interface_name=$.source_interface
  ),
  status_detail="duration " + $.duration,
  connection_info=dict(
    uid=$.message_number,
    direction=case(
      $.source_interface == "inside" and $.dest_interface == "outside" => "Outbound",
      $.source_interface == "outside" and $.dest_interface == "inside" => "Inbound",
      _ => "Lateral"
    ),
    direction_id=case(
      $.source_interface == "inside" and $.dest_interface == "outside" => 2,
      $.source_interface == "outside" and $.dest_interface == "inside" => 1,
      _ => 3
    ),
    protocol_name=lower($.protocol)
  ),
  timezone_offset=0
)
""");
    var msg113019Flow =
        asaHeaderParsedFlow
            .filter("$.message_number=='113019'")
            .parse(
                ParserConfigs.ParserConfig.builder()
                    .targetField("message_text")
                    .extractionConfig(
                        GrokExtractionConfig.builder()
                            .grokExpression(
                                "Group = %{WORD:group_name} , Username = %{USERNAME:username} , IP = %{IP:peer_address} , Session disconnected. Session Type: %{DATA:session_type} , Duration: %{TIME:duration} , Bytes xmt: %{NUMBER:bytes_xmt} , Bytes rcv: %{NUMBER:bytes_rcv} , Reason: %{GREEDYDATA:disconnect_reason}")
                            .build())
                    .build())
            .eval(
"""
dict(
  time=ts_str_to_epoch($.timestamp, 'MMM dd yyyy HH:mm:ss'),
  user=dict(
    name=$.username,
    type='User',
    domain=$.group_name,
    type_id=1
  ),
  proxy=dict(
    ip=$.peer_address,
    name='CiscoASA',
    type='Firewall',
    type_id=9,
    hostname='localhost'
  ),
  device=dict(
    ip=$.peer_address,
    name='CiscoASA',
    type='Firewall',
    type_id=9,
    hostname='localhost'
  ),
  status=case(
    str_contains($.message_text, 'Session disconnected') and $.disconnect_reason == 'User Requested' => 'User Requested',
    _ => null
  ),
  message=$.message_text,
  session=dict(
    uid=$.session_type + '-' + $.username + '-' + $.peer_address,
    is_vpn=case(
      $.session_type == 'IPsec' => true,
      _ => false
    ),
    created_time=case(
      str_contains($.message_text, 'Session disconnected') => ts_str_to_epoch($.timestamp, 'MMM dd yyyy HH:mm:ss') - duration_str_to_mills($.duration),
      _ => null
    ),
    expiration_time=case(
      str_contains($.message_text, 'Session disconnected') => ts_str_to_epoch($.timestamp, 'MMM dd yyyy HH:mm:ss'),
      _ => null
    ),
    expiration_reason=$.disconnect_reason
  ),
  metadata=dict(
    product=dict(
      name='Cisco ASA',
      vendor_name='Cisco'
    ),
    version="1.4.0",
    log_name='Security',
    event_code='113019',
    logged_time=ts_str_to_epoch($.timestamp, 'MMM dd yyyy HH:mm:ss'),
    log_provider='CiscoASA'
  ),
  type_uid=401402,
  class_uid=4014,
  status_id=case(
    str_contains($.message_text, 'Session disconnected') and $.disconnect_reason == 'User Requested' => 1,
    str_contains($.message_text, 'Session disconnected') => 2,
    _ => 99
  ),
  activity_id=case(
    str_contains($.message_text, 'Session disconnected') => 2,
    _ => 99
  ),
  severity_id=4,
  status_code=case(
    str_contains($.message_text, 'Session disconnected') and $.disconnect_reason == 'User Requested' => 'User Requested',
    _ => null
  ),
  tunnel_type=$.session_type,
  category_uid=4,
  dst_endpoint=dict(
    ip=$.peer_address,
    type='Server',
    type_id=1
  ),
  src_endpoint=dict(
    ip=$.peer_address,
    type='Unknown',
    owner=dict(
      name=$.username,
      domain=$.group_name
    ),
    type_id=0
  ),
  status_detail=$.disconnect_reason,
  tunnel_type_id=99,
  timezone_offset=0,
  tunnel_interface=dict(
    ip=$.peer_address,
    name='utun0',
    type='IPsec',
    type_id=4
  )
)
""");
    var msg113039Flow =
        asaHeaderParsedFlow
            .filter("$.message_number=='113039'")
            .parse(
                ParserConfigs.ParserConfig.builder()
                    .targetField("message_text")
                    .extractionConfig(
                        GrokExtractionConfig.builder()
                            .grokExpression(
                                "Group %{DATA:group_name} User %{USERNAME:username} IP %{IP:ip_address} AnyConnect parent session started.")
                            .build())
                    .build())
            .eval(
"""
dict(
  time=ts_str_to_epoch($.timestamp, "MMM dd yyyy HH:mm:ss"),
  user=dict(
    name=$.username,
    type="AnyConnect User",
    domain=$.group_name,
    type_id=1
  ),
  actor=dict(
    user=dict(
      name=$.username,
      type="AnyConnect User",
      domain=$.group_name,
      type_id=1
    ),
    app_name="AnyConnect"
  ),
  is_mfa=false,
  status=case(
    $.message_number == "113039" => "Started",
    _ => null
  ),
  message=$.message_text,
  service=dict(
    name="AnyConnect",
    labels=array(
      "VPN"
    )
  ),
  session=dict(
    uid="AnyConnect parent session",
    is_remote=true,
    created_time=ts_str_to_epoch($.timestamp, "MMM dd yyyy HH:mm:ss")
  ),
  metadata=dict(
    product=dict(
      name="Cisco ASA",
      vendor_name="Cisco"
    ),
    version="1.4.0",
    log_name="ASA-Security",
    event_code=$.message_number,
    logged_time=ts_str_to_epoch($.timestamp, "MMM dd yyyy HH:mm:ss"),
    log_provider=$.appName
  ),
  type_uid=300201,
  class_uid=3002,
  is_remote=true,
  status_id=case(
    $.message_number == "113039" => 1,
    _ => 0
  ),
  logon_type="Remote",
  activity_id=1,
  severity_id=case(
    $.level == '6' => 1,
    _ => 0
  ),
  status_code=$.message_number,
  category_uid=3,
  dst_endpoint=dict(
    ip=$.ip_address,
    type='Server',
    type_id=1
  ),
  src_endpoint=dict(
    ip=$.ip_address,
    type='Browser',
    owner=dict(
      name=$.username,
      domain=$.group_name
    ),
    type_id=8
  ),
  auth_protocol="AnyConnect",
  logon_type_id=3,
  status_detail=case(
    $.message_number == "113039" => "LOGON_SUCCESS",
    _ => null
  ),
  timezone_offset=0,
  auth_protocol_id=case(
    str_contains($.message_text, "AnyConnect") => 99,
    _ => 0
  )
)
""");
    var ocsfFlow =
        ZephFlow.merge(
            msg106023Flow,
            msg113019Flow,
            msg113039Flow,
            msg302013Flow,
            msg302014Flow,
            msg302015Flow,
            msg302016Flow,
            msg305011Flow,
            msg305012Flow);
    var outputFlow = ocsfFlow.stdoutSink(EncodingType.JSON_OBJECT);
    outputFlow.execute("job_id", "test_env", "test_service");
  }
}
