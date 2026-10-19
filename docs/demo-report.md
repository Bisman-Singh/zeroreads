# The OpenTelemetry demo's report

This is the report `zeroreads analyze` wrote for the OpenTelemetry demo run that the numbers in the
README come from. The demo's services ran on a local kind cluster, logging through the demo's own
Collector into Loki, with one dashboard of five panels, one Grafana alert and three ad-hoc queries
written for it, plus the three Loki ruler rules the test stack already had. All the traffic came from
the demo's own load generator, so no real user data is involved.

It is the file as written, except that its headings are one level deeper. Both evidence gaps it lists
were acknowledged in the demo's configuration. The token belonged to a service account in the one
Grafana organisation holding the demo's dashboard and alert, so it could not list other organisations
or read anyone's query history; the ad-hoc queries went straight to Loki, not through Explore.

## zeroreads report

Generated 2026-10-05T01:17:29Z. Discovery window 30m0s, evidence window 10m0s, drain v0.161.0.

46 rules decided, 29 act. Removes 21.4 MB/day.

### Evidence

- Query log: proven with a marker query; 8 distinct queries from 107 lines, oldest 2026-10-05T01:07:40Z
- Loki ruler: 3 rules
- Grafana: 6 stored queries against this Loki
- Sink `otlp_http/loki: analysed Loki`

### Evidence gaps

Each blocks every rule until fixed or acknowledged in `policy.acknowledge`.

- `grafana-orgs:localhost:13000` (grafana `org 7 orgs`): `these credentials cannot list organisations (HTTP 403), so only org 7 was read; dashboards, alerts and links in any other org are unseen. Use a server admin's credentials, or acknowledge if this Grafana has one org`
- `grafana-queryhistory:localhost:13000` (grafana `org 7 queryhistory`): `only the history of the user these credentials belong to is readable`

### Readers

21 readers across all rules. 6 read the rule's lines exactly (each shows a line it reads). 15 are assumed to read more than they may, because part of the query is not modelled; each of those can block a rule that is in fact safe:

- stream selector without the scope label: 14
- case-insensitive filter: 8

### Rules

#### r-2c50fb6930db `Setting new leader for topicId <*> partition <*> to 1 using ELR. Previous partition: PartitionRegistration(replicas=[1], directories=[7z1E8uCZvYYqhmiJ9r8FQg], isr=[], removingReplicas=[], addingReplicas=[], elr=[1], lastKnownElr=[1], leader=-1, leaderRecoveryState=RECOVERED, <*> <*> change record: <*> <*> isr=null, leader=-2, replicas=null, removingReplicas=null, addingReplicas=null, leaderRecoveryState=-1, directories=null, eligibleLeaderReplicas=null, lastKnownElr=null)` (`kafka`)

- Action: **aggregate**
- Language: `\ASetting new leader for topicId (?:RhiPV270QOCLwx_wFneXzw,|ed3ytlKeTYCx9U8PrgQ99g,) partition [0-9]{1,2} to 1 using ELR\. Previous partition: PartitionRegistration\(replicas=\[1\], directories=\[7z1E8uCZvYYqhmiJ9r8FQg\], isr=\[\], removingReplicas=\[\], addingReplicas=\[\], elr=\[1\], lastKnownElr=\[1\], leader=-1, leaderRecoveryState=RECOVERED, (?:leaderEpoch=1,|leaderEpoch=3,|leaderEpoch=5,|leaderEpoch=7,) (?:partitionEpoch=1\),|partitionEpoch=3\),|partitionEpoch=5\),|partitionEpoch=7\),) change record: PartitionChangeRecord\(partitionId=[0-9]{1,2}, (?:topicId=RhiPV270QOCLwx_wFneXzw,|topicId=ed3ytlKeTYCx9U8PrgQ99g,) isr=null, leader=-2, replicas=null, removingReplicas=null, addingReplicas=null, leaderRecoveryState=-1, directories=null, eligibleLeaderReplicas=null, lastKnownElr=null\)\z`
- Volume: 204 lines, 118.8 KB over 30m0s
- Removes 5.7 MB/day

#### r-a1f0ed72fb5c `[GroupCoordinator id=1] <*> unloading metadata for <*> with epoch <*>` (`kafka`)

- Action: **aggregate**
- Language: `\A\[GroupCoordinator id=1\] (?:Finished|Started) unloading metadata for __consumer_offsets-[0-9]{1,2} with epoch (?:OptionalInt\[1\]\.|OptionalInt\[3\]\.|OptionalInt\[5\]\.|OptionalInt\[7\]\.)\z`
- Volume: 400 lines, 41.3 KB over 30m0s
- Removes 2.0 MB/day

#### r-5cc9e0356e9c `[GroupCoordinator id=1] Scheduling <*> of metadata <*> <*> with epoch <*>` (`kafka`)

- Action: **aggregate**
- Language: `\A\[GroupCoordinator id=1\] Scheduling (?:loading|unloading) of metadata (?:for|from) __consumer_offsets-[0-9]{1,2} with epoch (?:2|4|6|8|OptionalInt\[1\]|OptionalInt\[3\]|OptionalInt\[5\]|OptionalInt\[7\])\z`
- Volume: 400 lines, 40.3 KB over 30m0s
- Removes 1.9 MB/day

#### r-80cb30851bc9 `[GroupCoordinator id=1] Finished loading of metadata from <*> with epoch <*> in <*> where <*> was spent in the scheduler. Loaded <*> records which total to <*> bytes.` (`kafka`)

- Action: **aggregate**
- Language: `\A\[GroupCoordinator id=1\] Finished loading of metadata from __consumer_offsets-[0-9]{1,2} with epoch (?:2|4|6|8) in [0-9]{1,3}ms where [0-9]{1,3}ms was spent in the scheduler\. Loaded (?:0|108|15|17|55|74|9) records which total to (?:0|10704|1371|15532|2193|2467|8006) bytes\.\z`
- Volume: 184 lines, 33.0 KB over 30m0s
- Removes 1.6 MB/day

#### r-1c1f1c1baf2e `Receive ListRecommendations for product <*> <*> <*> <*> <*>` (`recommendation`)

- Action: **aggregate**
- Language: `\AReceive ListRecommendations for product (?:ids:\['0PUK6V6EV0',|ids:\['1YMWWN1N4O',|ids:\['2ZYFJ3GM2N',|ids:\['66VCHSJNUP',|ids:\['6E92ZMYYFZ',|ids:\['9SIQT8TOJO',|ids:\['HQTGWGPNH4',|ids:\['L9ECAV7KIM',|ids:\['LS4PSXUNUM',|ids:\['OLJCESPC7Z',) (?:'0PUK6V6EV0',|'1YMWWN1N4O',|'2ZYFJ3GM2N',|'66VCHSJNUP',|'6E92ZMYYFZ',|'9SIQT8TOJO',|'HQTGWGPNH4',|'L9ECAV7KIM',|'LS4PSXUNUM',|'OLJCESPC7Z',) (?:'0PUK6V6EV0',|'1YMWWN1N4O',|'2ZYFJ3GM2N',|'66VCHSJNUP',|'6E92ZMYYFZ',|'9SIQT8TOJO',|'HQTGWGPNH4',|'L9ECAV7KIM',|'LS4PSXUNUM',|'OLJCESPC7Z',) (?:'0PUK6V6EV0',|'1YMWWN1N4O',|'2ZYFJ3GM2N',|'66VCHSJNUP',|'6E92ZMYYFZ',|'9SIQT8TOJO',|'HQTGWGPNH4',|'L9ECAV7KIM',|'LS4PSXUNUM',|'OLJCESPC7Z',) (?:'0PUK6V6EV0'\]|'1YMWWN1N4O'\]|'2ZYFJ3GM2N'\]|'66VCHSJNUP'\]|'6E92ZMYYFZ'\]|'9SIQT8TOJO'\]|'HQTGWGPNH4'\]|'L9ECAV7KIM'\]|'LS4PSXUNUM'\]|'OLJCESPC7Z'\])\z`
- Volume: 260 lines, 29.6 KB over 30m0s
- Removes 1.4 MB/day

#### r-e133b172cd40 `API request completed` (`frontend`)

- Action: **none**
- Language: `\AAPI request completed\z`
- Volume: 1252 lines, 26.3 KB over 30m0s
- Blocked: `together with the other rules of frontend, removing these lines would empty 1 streams`

#### r-20591c713070 `[RaftLog partition=__cluster_metadata-0, nodeId=1] Marking snapshot <*> epoch=1] for deletion because its timestamp <*> is now <*> older than the retention (60000)` (`kafka`)

- Action: **aggregate**
- Language: `\A\[RaftLog partition=__cluster_metadata-0, nodeId=1\] Marking snapshot OffsetAndEpoch\[offset=[0-9]{3,4}, epoch=1\] for deletion because its timestamp \([0-9]{13}\) is now \([0-9]{13}\) older than the retention \(60000\)\z`
- Volume: 88 lines, 18.6 KB over 30m0s
- Removes 890.4 KB/day

#### r-da74f052bc91 `Product Found` (`product-catalog`)

- Action: **none**
- Language: `\AProduct Found\z`
- Volume: 1403 lines, 18.2 KB over 30m0s
- Blocked: `together with the other rules of product-catalog, removing these lines would empty 1 streams`

#### r-0633e5195218 `[LocalLog partition=__cluster_metadata-0, dir=/tmp/kafka-logs/__cluster_metadata-0] Rolled new log segment at offset <*> in <*> ms.` (`kafka`)

- Action: **aggregate**
- Language: `\A\[LocalLog partition=__cluster_metadata-0, dir=/tmp/kafka-logs/__cluster_metadata-0\] Rolled new log segment at offset [0-9]{3,4} in [0-9]{1,5} ms\.\z`
- Volume: 116 lines, 15.2 KB over 30m0s
- Removes 731.3 KB/day

#### r-e47e1d031435 `[ProducerStateManager partition=__cluster_metadata-0] Wrote producer snapshot at offset <*> with 0 producer ids in <*> ms.` (`kafka`)

- Action: **aggregate**
- Language: `\A\[ProducerStateManager partition=__cluster_metadata-0\] Wrote producer snapshot at offset [0-9]{3,4} with 0 producer ids in (?:0|1|10|14|17|2|3|38|4|57|7|79|8) ms\.\z`
- Volume: 116 lines, 14.0 KB over 30m0s
- Removes 673.2 KB/day

#### r-dae52bddd6da `[SnapshotGenerator id=1] Creating new KRaft snapshot file snapshot <*> because we have replayed at least 2800 bytes.` (`kafka`)

- Action: **aggregate**
- Language: `\A\[SnapshotGenerator id=1\] Creating new KRaft snapshot file snapshot [0-9]{20}-0000000001 because we have replayed at least 2800 bytes\.\z`
- Volume: 89 lines, 12.8 KB over 30m0s
- Removes 615.2 KB/day

#### r-6b4c531fd885 `[UnifiedLog partition=__cluster_metadata-0, dir=/tmp/kafka-logs] Deleting segments due to log start offset <*> breach: <*> <*> <*> <*>` (`kafka`)

- Action: **aggregate**
- Language: `\A\[UnifiedLog partition=__cluster_metadata-0, dir=/tmp/kafka-logs\] Deleting segments due to log start offset [0-9]{3,4} breach: LogSegment\(baseOffset=[0-9]{3,4}, (?:size=1700,|size=1894,|size=1944,|size=2016,|size=2088,|size=2160,|size=4736,|size=7566,) lastModifiedTime=[0-9]{13}, largestRecordTimestamp=[0-9]{13}\)\z`
- Volume: 55 lines, 12.5 KB over 30m0s
- Removes 601.0 KB/day

#### r-2f40a875fc56 `Deleted producer state snapshot <*>` (`kafka`)

- Action: **aggregate**
- Language: `\ADeleted producer state snapshot /tmp/kafka-logs/__cluster_metadata-0/[0-9]{20}\.snapshot\.deleted\z`
- Volume: 113 lines, 12.0 KB over 30m0s
- Removes 574.9 KB/day

#### r-46922b6c469c `[LocalLog partition=__cluster_metadata-0, dir=/tmp/kafka-logs/__cluster_metadata-0] Deleting segment files <*> <*> <*> <*>` (`kafka`)

- Action: **aggregate**
- Language: `\A\[LocalLog partition=__cluster_metadata-0, dir=/tmp/kafka-logs/__cluster_metadata-0\] Deleting segment files LogSegment\(baseOffset=[0-9]{1,4}, (?:size=1700,|size=1894,|size=1944,|size=2016,|size=2088,|size=2160,|size=3060,|size=4736,|size=5601,|size=7566,) lastModifiedTime=[0-9]{13}, largestRecordTimestamp=[0-9]{13}\)\z`
- Volume: 55 lines, 11.8 KB over 30m0s
- Removes 566.9 KB/day

#### r-7ed7864a8d20 `[UnifiedLog partition=__cluster_metadata-0, dir=/tmp/kafka-logs] Incremented log start offset to <*> due to snapshot generated` (`kafka`)

- Action: **aggregate**
- Language: `\A\[UnifiedLog partition=__cluster_metadata-0, dir=/tmp/kafka-logs\] Incremented log start offset to [0-9]{3,4} due to snapshot generated\z`
- Volume: 88 lines, 11.2 KB over 30m0s
- Removes 535.6 KB/day

#### r-ab44d2ebc244 `Traces` (`otelcol-contrib`)

- Action: **aggregate**
- Language: `\ATraces\z`
- Volume: 1662 lines, 10.0 KB over 30m0s
- Removes 478.7 KB/day

#### r-b6bbe742163c `[UnifiedLog partition=__cluster_metadata-0, dir=/tmp/kafka-logs] Deleting segments due to log start offset <*> breach: <*> <*> <*> <*> <*> <*> <*>` (`kafka`)

- Action: **aggregate**
- Language: `\A\[UnifiedLog partition=__cluster_metadata-0, dir=/tmp/kafka-logs\] Deleting segments due to log start offset [0-9]{3,4} breach: LogSegment\(baseOffset=[0-9]{3,4}, (?:size=1628,|size=1894,|size=2088,|size=2160,|size=8929,) lastModifiedTime=[0-9]{13}, largestRecordTimestamp=[0-9]{13}\),LogSegment\(baseOffset=[0-9]{3,4}, size=[0-9]{3,4}, lastModifiedTime=[0-9]{13}, largestRecordTimestamp=[0-9]{13}\)\z`
- Volume: 28 lines, 9.4 KB over 30m0s
- Removes 452.0 KB/day

#### r-15781988041f `Deleted log <*>` (`kafka`)

- Action: **aggregate**
- Language: `\ADeleted log /tmp/kafka-logs/__cluster_metadata-0/[0-9]{20}\.log\.deleted\.\z`
- Volume: 114 lines, 9.3 KB over 30m0s
- Removes 448.7 KB/day

#### r-041423b5aee6 `[LocalLog partition=__cluster_metadata-0, dir=/tmp/kafka-logs/__cluster_metadata-0] Deleting segment files <*> <*> <*> <*> <*> <*> <*> <*>` (`kafka`)

- Action: **aggregate**
- Language: `\A\[LocalLog partition=__cluster_metadata-0, dir=/tmp/kafka-logs/__cluster_metadata-0\] Deleting segment files LogSegment\(baseOffset=[0-9]{3,4}, (?:size=1628,|size=1894,|size=2041,|size=2088,|size=2160,|size=8929,) lastModifiedTime=[0-9]{13}, largestRecordTimestamp=[0-9]{13}\), LogSegment\(baseOffset=[0-9]{3,4}, size=[0-9]{3,4}, lastModifiedTime=[0-9]{13}, largestRecordTimestamp=[0-9]{13}\)\z`
- Volume: 28 lines, 9.1 KB over 30m0s
- Removes 436.1 KB/day

#### r-5b3aab32acae `[SnapshotEmitter id=1] Successfully wrote snapshot <*>` (`kafka`)

- Action: **aggregate**
- Language: `\A\[SnapshotEmitter id=1\] Successfully wrote snapshot [0-9]{20}-0000000001\z`
- Volume: 89 lines, 7.3 KB over 30m0s
- Removes 350.3 KB/day

#### r-348da4c67c70 `Metrics` (`otelcol-contrib`)

- Action: **aggregate**
- Language: `\AMetrics\z`
- Volume: 972 lines, 6.8 KB over 30m0s
- Removes 326.6 KB/day

#### r-65c6e3183dfe `Deleted snapshot files for snapshot <*> epoch=1].` (`kafka`)

- Action: **aggregate**
- Language: `\ADeleted snapshot files for snapshot OffsetAndEpoch\[offset=[0-9]{2,4}, epoch=1\]\.\z`
- Volume: 88 lines, 6.4 KB over 30m0s
- Removes 307.2 KB/day

#### r-a54de395e819 `[QuorumController id=1] In the last 60000 ms period, <*> controller events were completed, which took an average of <*> ms each. The slowest event was <*> which took <*> ms.` (`kafka`)

- Action: **aggregate**
- Language: `\A\[QuorumController id=1\] In the last 60000 ms period, [0-9]{3} controller events were completed, which took an average of [0-9]{2,4}\.[0-9]{2} ms each\. The slowest event was writeNoOpRecord\([0-9]{7,10}\), which took [0-9]{2,5}\.[0-9]{2} ms\.\z`
- Volume: 29 lines, 5.9 KB over 30m0s
- Removes 282.5 KB/day

#### r-a1bec2ac3880 `conversion successful` (`currency`)

- Action: **none**
- Language: `\Aconversion successful\z`
- Volume: 204 lines, 4.3 KB over 30m0s
- Blocked: `1 of 1 streams hold only these lines; removing them would make those streams disappear`

#### r-18efa1686a53 `Found 10 products from database` (`product-catalog`)

- Action: **none**
- Language: `\AFound 10 products from database\z`
- Volume: 130 lines, 4.0 KB over 30m0s
- Blocked: `together with the other rules of product-catalog, removing these lines would empty 1 streams`

#### r-4c03b897cd28 `Order confirmation email sent` (`email`)

- Action: **none**
- Language: `\AOrder confirmation email sent\z`
- Volume: 72 lines, 2.1 KB over 30m0s
- Blocked: `1 of 1 streams hold only these lines; removing them would make those streams disappear`

#### r-11805f2dcc10 `Order placed successfully` (`frontend`)

- Action: **none**
- Language: `\AOrder placed successfully\z`
- Volume: 72 lines, 1.8 KB over 30m0s
- Blocked: `together with the other rules of frontend, removing these lines would empty 1 streams`

#### r-4ddfc6a7ad54 `sending to postProcessor` (`checkout`)

- Action: **aggregate**
- Language: `\Asending to postProcessor\z`
- Volume: 72 lines, 1.7 KB over 30m0s
- Removes 82.9 KB/day

#### r-5a3cdcc54faf `Charge request received.` (`payment`)

- Action: **aggregate**
- Language: `\ACharge request received\.\z`
- Volume: 72 lines, 1.7 KB over 30m0s
- Removes 82.9 KB/day

#### r-eb823bb05af9 `order confirmation email sent` (`checkout`)

- Action: **aggregate**
- Language: `\Aorder confirmation email sent\z`
- Volume: 55 lines, 1.6 KB over 30m0s
- Removes 76.6 KB/day

#### r-7e294626dd44 `payment went through` (`checkout`)

- Action: **aggregate**
- Language: `\Apayment went through\z`
- Volume: 72 lines, 1.4 KB over 30m0s
- Removes 69.1 KB/day

#### r-9da63e72b44d `Tracking ID Created` (`shipping`)

- Action: **aggregate**
- Language: `\ATracking ID Created\z`
- Volume: 72 lines, 1.4 KB over 30m0s
- Removes 65.7 KB/day

#### r-d18e8bcc9f6a `Sending Quote` (`shipping`)

- Action: **aggregate**
- Language: `\ASending Quote\z`
- Volume: 72 lines, 936.0 B over 30m0s
- Removes 44.9 KB/day

#### r-391cbc407565 `[PlaceOrder]` (`checkout`)

- Action: **aggregate**
- Language: `\A\[PlaceOrder\]\z`
- Volume: 72 lines, 864.0 B over 30m0s
- Removes 41.5 KB/day

#### r-cb9804a8feb3 `order placed` (`checkout`)

- Action: **aggregate**
- Language: `\Aorder placed\z`
- Volume: 72 lines, 864.0 B over 30m0s
- Removes 41.5 KB/day

#### r-0c0199da2bc9 `[Broker id=1] Follower <*> starts at leader epoch <*> from offset <*> with partition epoch <*> and high watermark <*> Current leader is -1. Previous leader Some(1) and previous leader epoch was <*>` (`kafka`)

- Action: **none**
- Language: `\A\[Broker id=1\] Follower [0-9A-Za-z_.\-]{8,21} starts at leader epoch (?:1|3|5|7) from offset (?:0|108|15|17|18|21|55|74|8|9) with partition epoch (?:1|3|5|7) and high watermark (?:0\.|108\.|15\.|17\.|18\.|21\.|55\.|74\.|8\.|9\.) Current leader is -1\. Previous leader Some\(1\) and previous leader epoch was (?:0\.|2\.|4\.|6\.)\z`
- Volume: 204 lines, 42.2 KB over 30m0s
- Blocked: `2 queries read these lines`
- Blocked: `lines can be error-like, e.g. "[Broker id=1] Follower -----ERR starts at leader epoch 1 from offset 0 with partition epoch 1 and high watermark 0. Current leader is -1. Previous leader Some(1) and previous leader epoch was 0."`
  - loki-querylog `query-log (frontend)`: `{k8s_namespace_name="zeroreads-demo"} |= "timeout"` reads e.g. `[Broker id=1] Follower -timeout starts at leader epoch 1 from offset 0 with partition epoch 1 and high watermark 0. Current leader is -1. Previous leader Some(1) and previous leader epoch was 0.` (assumed: `stream selector names no scope label (service_name); assumed to select the rule's streams`)
  - grafana `http://localhost:13000 org 7 dashboard:shop-logs/panel:2/A`: `sum by (service_name) (count_over_time({k8s_namespace_name="zeroreads-demo"} |~ "(?i)error" [$__auto]))` counts e.g. `[Broker id=1] Follower ---ERROR starts at leader epoch 1 from offset 0 with partition epoch 1 and high watermark 0. Current leader is -1. Previous leader Some(1) and previous leader epoch was 0.` (assumed: `stream selector names no scope label (service_name); assumed to select the rule's streams; case-insensitive filter "(?i)error" is modelled as both of Loki's readings`)

#### r-2054960da8c0 `Transaction complete.` (`payment`)

- Action: **none**
- Language: `\ATransaction complete\.\z`
- Volume: 72 lines, 1.5 KB over 30m0s
- Blocked: `1 query read these lines`
  - grafana `http://localhost:13000 org 7 dashboard:shop-logs/panel:5/A`: `sum(count_over_time({service_name="payment"} |= "Transaction" [$__auto]))` counts e.g. `Transaction complete.`

#### r-2ffa58160141 `Consumed record with orderId: <*> and updated total count to: <*>` (`fraud-detection`)

- Action: **none**
- Language: `\AConsumed record with orderId: [^ ]{37} and updated total count to: [0-9]{1,2}\z`
- Volume: 72 lines, 7.1 KB over 30m0s
- Blocked: `2 queries read these lines`
- Blocked: `lines can be error-like, e.g. "Consumed record with orderId: \x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00ERR and updated total count to: 0"`
  - loki-querylog `query-log (frontend)`: `{k8s_namespace_name="zeroreads-demo"} |= "timeout"` reads e.g. `Consumed record with orderId: \x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00timeout and updated total count to: 0` (assumed: `stream selector names no scope label (service_name); assumed to select the rule's streams`)
  - grafana `http://localhost:13000 org 7 dashboard:shop-logs/panel:2/A`: `sum by (service_name) (count_over_time({k8s_namespace_name="zeroreads-demo"} |~ "(?i)error" [$__auto]))` counts e.g. `Consumed record with orderId: \x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00ERROR and updated total count to: 0` (assumed: `stream selector names no scope label (service_name); assumed to select the rule's streams; case-insensitive filter "(?i)error" is modelled as both of Loki's readings`)

#### r-3252f90aa816 `Deleted <*> index <*>` (`kafka`)

- Action: **none**
- Language: `\ADeleted (?:offset|time) index /tmp/kafka-logs/__cluster_metadata-0/[0-9]{20}\.[a-z]{5,9}\.deleted\.\z`
- Volume: 228 lines, 21.4 KB over 30m0s
- Blocked: `2 queries read these lines`
- Blocked: `lines can be error-like, e.g. "Deleted time index /tmp/kafka-logs/__cluster_metadata-0/00000000000000000000.alert.deleted."`
  - loki-querylog `query-log (frontend)`: `{k8s_namespace_name="zeroreads-demo"} |= "timeout"` reads e.g. `Deleted time index /tmp/kafka-logs/__cluster_metadata-0/00000000000000000000.timeout.deleted.` (assumed: `stream selector names no scope label (service_name); assumed to select the rule's streams`)
  - grafana `http://localhost:13000 org 7 dashboard:shop-logs/panel:2/A`: `sum by (service_name) (count_over_time({k8s_namespace_name="zeroreads-demo"} |~ "(?i)error" [$__auto]))` counts e.g. `Deleted time index /tmp/kafka-logs/__cluster_metadata-0/00000000000000000000.error.deleted.` (assumed: `stream selector names no scope label (service_name); assumed to select the rule's streams; case-insensitive filter "(?i)error" is modelled as both of Loki's readings`)

#### r-47f450ceeb5e `Exporting failed. Will retry the request after interval.` (`otelcol-contrib`)

- Action: **none**
- Language: `\AExporting failed\. Will retry the request after interval\.\z`
- Volume: 30 lines, 1.7 KB over 30m0s
- Blocked: `lines can be error-like, e.g. "Exporting failed. Will retry the request after interval."`

#### r-580c641ba05f `Successful to write message. offset: 0, duration: <*>` (`checkout`)

- Action: **none**
- Language: `\ASuccessful to write message\. offset: 0, duration: [^ ]{8,11}\z`
- Volume: 72 lines, 4.3 KB over 30m0s
- Blocked: `6 queries read these lines`
- Blocked: `lines can be error-like, e.g. "Successful to write message. offset: 0, duration: \x00\x00\x00\x00\x00ERR"`
  - loki-querylog `query-log (frontend)`: `{k8s_namespace_name="zeroreads-demo"} |= "timeout"` reads e.g. `Successful to write message. offset: 0, duration: \x00timeout` (assumed: `stream selector names no scope label (service_name); assumed to select the rule's streams`)
  - loki-ruler `rules.yaml/checkout/HealthzMissing (alert)`: `absent_over_time({service_name="checkout"} |= "healthz" [5m])` counts e.g. `Successful to write message. offset: 0, duration: \x00healthz`
  - loki-ruler `rules.yaml/checkout/PaymentsDeclined (alert)`: `sum(count_over_time({service_name="checkout"} |= "declined" [5m])) > 100` counts e.g. `Successful to write message. offset: 0, duration: declined`
  - loki-ruler `rules.yaml/checkout/checkout:requests:rate1m (record)`: `sum(rate({service_name="checkout"} |= "status" [1m]))` counts e.g. `Successful to write message. offset: 0, duration: \x00\x00status`
  - grafana `http://localhost:13000 org 7 dashboard:shop-logs/panel:1/A`: `{service_name="checkout"} |~ "(?i)(error|fail)"` reads e.g. `Successful to write message. offset: 0, duration: \x00\x00\x00\x00FAIL` (assumed: `case-insensitive filter "(?i)(error|fail)" is modelled as both of Loki's readings`)
  - grafana `http://localhost:13000 org 7 dashboard:shop-logs/panel:2/A`: `sum by (service_name) (count_over_time({k8s_namespace_name="zeroreads-demo"} |~ "(?i)error" [$__auto]))` counts e.g. `Successful to write message. offset: 0, duration: \x00\x00\x00ERROR` (assumed: `stream selector names no scope label (service_name); assumed to select the rule's streams; case-insensitive filter "(?i)error" is modelled as both of Loki's readings`)

#### r-652a227478c5 `Targeted ad request received for <*>` (`ad`)

- Action: **none**
- Language: `\ATargeted ad request received for (?:\[accessories\]|\[assembly\]|\[binoculars\]|\[books\]|\[telescopes\]|\[travel\])\z`
- Volume: 80 lines, 3.5 KB over 30m0s
- Blocked: `1 query read these lines`
  - loki-querylog `query-log (frontend)`: `{service_name="ad"}` reads e.g. `Targeted ad request received for [books]`

#### r-6ab5dd563b47 `Requesting quote` (`shipping`)

- Action: **none**
- Language: `\ARequesting quote\z`
- Volume: 72 lines, 1.2 KB over 30m0s
- Blocked: `1 query read these lines`
  - loki-querylog `query-log (frontend)`: `{service_name="shipping"} |= "quote"` reads e.g. `Requesting quote`

#### r-a874b894d477 `<*> <*> <*> HTTP/1.1" <*> <*> <*> - "-" <*> <*> <*> <*> "-" "python-requests/2.34.2" <*> "frontend-proxy:8080" "10.96.84.92:8080" frontend <*> 10.244.0.110:8080 <*> - -` (`frontend-proxy`)

- Action: **none**
- Language: `\A\[2026-10-05T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z\] (?:"GET|"POST) [^ ]{1,42} HTTP/1\.1" (?:200|308|503|504) (?:-|UC|UT) (?:response_timeout|upstream_reset_before_response_started\{connection_termination\}|via_upstream) - "-" (?:0|102|103|372|380|382|385|386|388|395|404) [0-9]{1,4} [0-9]{1,5} [0-9A-Za-z_.\-]{1,5} "-" "python-requests/2\.34\.2" [^ ]{38} "frontend-proxy:8080" "10\.96\.84\.92:8080" frontend 10\.244\.0\.110:[0-9]{5} 10\.244\.0\.110:8080 (?:10\.244\.0\.103:43766|10\.244\.0\.103:43768|10\.244\.0\.103:43774|10\.244\.0\.103:51924|10\.244\.0\.103:51926) - -\n\z`
- Volume: 1384 lines, 388.8 KB over 30m0s
- Blocked: `2 queries read these lines`
- Blocked: `lines can be error-like, e.g. "[2026-10-05T00:00:00.000Z] \"GET \x00 HTTP/1.1\" 200 - via_upstream - \"-\" 0 0 0 - \"-\" \"python-requests/2.34.2\" \x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00ERR \"frontend-proxy:8080\" \"10.96.84.92:8080\" frontend 10.244.0.110:00000 10.244.0.110:8080 10.244.0.103:43766 - -\n"`
  - loki-querylog `query-log (frontend)`: `{k8s_namespace_name="zeroreads-demo"} |= "timeout"` reads e.g. `[2026-10-05T00:00:00.000Z] "GET \x00 HTTP/1.1" 200 - via_upstream - "-" 0 0 0 - "-" "python-requests/2.34.2" \x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00timeout "frontend-proxy:8080" "10.96.84.92:8080" frontend 10.244.0.110:00000 10.244.0.110:8080 10.244.0.103:43766 - -\n` (assumed: `stream selector names no scope label (service_name); assumed to select the rule's streams`)
  - grafana `http://localhost:13000 org 7 dashboard:shop-logs/panel:2/A`: `sum by (service_name) (count_over_time({k8s_namespace_name="zeroreads-demo"} |~ "(?i)error" [$__auto]))` counts e.g. `[2026-10-05T00:00:00.000Z] "GET \x00 HTTP/1.1" 200 - via_upstream - "-" 0 0 0 - "-" "python-requests/2.34.2" \x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00ERROR "frontend-proxy:8080" "10.96.84.92:8080" frontend 10.244.0.110:00000 10.244.0.110:8080 10.244.0.103:43766 - -\n` (assumed: `stream selector names no scope label (service_name); assumed to select the rule's streams; case-insensitive filter "(?i)error" is modelled as both of Loki's readings`)

#### r-be37b091e5da `[QuorumController id=1] Exceptionally slow controller event <*> took <*> ms.` (`kafka`)

- Action: **none**
- Language: `\A\[QuorumController id=1\] Exceptionally slow controller event [A-Za-z]{15,22}\([0-9]{8,10}\) took [0-9]{4,5} ms\.\z`
- Volume: 70 lines, 7.2 KB over 30m0s
- Blocked: `2 queries read these lines`
- Blocked: `sampled lines carry severity ERROR`
  - loki-querylog `query-log (frontend)`: `{k8s_namespace_name="zeroreads-demo"} |= "timeout"` reads e.g. `[QuorumController id=1] Exceptionally slow controller event AAAAAAAAtimeout(00000000) took 0000 ms.` (assumed: `stream selector names no scope label (service_name); assumed to select the rule's streams`)
  - grafana `http://localhost:13000 org 7 dashboard:shop-logs/panel:2/A`: `sum by (service_name) (count_over_time({k8s_namespace_name="zeroreads-demo"} |~ "(?i)error" [$__auto]))` counts e.g. `[QuorumController id=1] Exceptionally slow controller event AAAAAAAAAAERROR(00000000) took 0000 ms.` (assumed: `stream selector names no scope label (service_name); assumed to select the rule's streams; case-insensitive filter "(?i)error" is modelled as both of Loki's readings`)

#### r-d84a91fe8c9f `[Broker id=1] Leader <*> with topic id <*> starts at leader epoch <*> from offset <*> with partition epoch <*> high watermark <*> ISR [1], adding replicas [] and removing replicas [] . Previous leader Some(-1) and previous leader epoch was <*>` (`kafka`)

- Action: **none**
- Language: `\A\[Broker id=1\] Leader [0-9A-Za-z_.\-]{8,21} with topic id (?:Some\(RhiPV270QOCLwx_wFneXzw\)|Some\(ed3ytlKeTYCx9U8PrgQ99g\)) starts at leader epoch (?:2|4|6|8) from offset (?:0|108|15|17|18|21|55|74|8|9) with partition epoch (?:2,|4,|6,|8,) high watermark (?:0,|108,|15,|17,|18,|21,|55,|74,|8,|9,) ISR \[1\], adding replicas \[\] and removing replicas \[\] \. Previous leader Some\(-1\) and previous leader epoch was (?:1\.|3\.|5\.|7\.)\z`
- Volume: 204 lines, 56.8 KB over 30m0s
- Blocked: `2 queries read these lines`
- Blocked: `lines can be error-like, e.g. "[Broker id=1] Leader -----ERR with topic id Some(RhiPV270QOCLwx_wFneXzw) starts at leader epoch 2 from offset 0 with partition epoch 2, high watermark 0, ISR [1], adding replicas [] and removing replicas [] . Previous leader Some(-1) and previous leader epoch was 1."`
  - loki-querylog `query-log (frontend)`: `{k8s_namespace_name="zeroreads-demo"} |= "timeout"` reads e.g. `[Broker id=1] Leader -timeout with topic id Some(RhiPV270QOCLwx_wFneXzw) starts at leader epoch 2 from offset 0 with partition epoch 2, high watermark 0, ISR [1], adding replicas [] and removing replicas [] . Previous leader Some(-1) and previous leader epoch was 1.` (assumed: `stream selector names no scope label (service_name); assumed to select the rule's streams`)
  - grafana `http://localhost:13000 org 7 dashboard:shop-logs/panel:2/A`: `sum by (service_name) (count_over_time({k8s_namespace_name="zeroreads-demo"} |~ "(?i)error" [$__auto]))` counts e.g. `[Broker id=1] Leader ---ERROR with topic id Some(RhiPV270QOCLwx_wFneXzw) starts at leader epoch 2 from offset 0 with partition epoch 2, high watermark 0, ISR [1], adding replicas [] and removing replicas [] . Previous leader Some(-1) and previous leader epoch was 1.` (assumed: `stream selector names no scope label (service_name); assumed to select the rule's streams; case-insensitive filter "(?i)error" is modelled as both of Loki's readings`)

### Templates without a rule

- `ad` `Non-targeted ad request received, preparing random response.`: `rule: too few aligned samples: 17 aligned of 17 (need 20)`
- `checkout` `Closed connection to broker kafka:9092`: `rule: too few aligned samples: 1 aligned of 1 (need 20)`
- `checkout` `client/metadata fetching metadata for all topics from broker kafka:9092`: `rule: too few aligned samples: 3 aligned of 3 (need 20)`
- `checkout` `client/seedbrokers close seed broker #-1 at kafka:9092 due to socket error: broken pipe`: `rule: too few aligned samples: 1 aligned of 1 (need 20)`
- `checkout` `failed to send order confirmation: failed POST to email service: Post "http://email:8080/send_order_confirmation": context deadline exceeded`: `rule: too few aligned samples: 17 aligned of 17 (need 20)`
- `kafka` `Recorded new KRaft controller, from now on will use node kafka:9093 (id: 1 rack: null isFenced: false)`: `rule: too few aligned samples: 12 aligned of 12 (need 20)`
- `kafka` `[Broker id=1] <*> fetchers as part of become-follower for 51 partitions`: `rule: too few aligned samples: 8 aligned of 8 (need 20)`
- `kafka` `[Broker id=1] Transitioning 51 partition(s) to local <*>`: `rule: too few aligned samples: 8 aligned of 8 (need 20)`
- `kafka` `[BrokerLifecycleManager id=1] Unable to send a heartbeat because the RPC got timed out before it could be sent.`: `rule: too few aligned samples: 12 aligned of 12 (need 20)`
- `kafka` `[GroupCoordinator id=1 topic=__consumer_offsets <*> <*> Unloading group metadata for generation 1.`: `rule: too few aligned samples: 7 aligned of 7 (need 20)`
- `kafka` `[GroupCoordinator id=1 topic=__consumer_offsets <*> Loaded classic group <*> with 1 members.`: `rule: too few aligned samples: 6 aligned of 6 (need 20)`
- `kafka` `[GroupCoordinator id=1] Failed to load metadata from <*> with epoch 2 due to Stopped loading records from <*> because the partition is not online or is no longer the leader..`: `rule: too few aligned samples: 16 aligned of 16 (need 20)`
- `kafka` `[LocalLog partition=__cluster_metadata-0, dir=/tmp/kafka-logs/__cluster_metadata-0] Deleting segment files LogSegment(baseOffset=1464, size=1024, lastModifiedTime=1791161753649, largestRecordTimestamp=1791161753561), LogSegment(baseOffset=1485, size=985, lastModifiedTime=1791161769863, largestRecordTimestamp=1791161769060), LogSegment(baseOffset=1508, size=2924, lastModifiedTime=1791161795432, largestRecordTimestamp=1791161776553)`: `rule: too few aligned samples: 1 aligned of 1 (need 20)`
- `kafka` `[NodeToControllerChannelManager id=1 <*> Node 1 disconnected.`: `rule: too few aligned samples: 2 aligned of 2 (need 20)`
- `kafka` `[NodeToControllerChannelManager id=1 name=heartbeat] Cancelled in-flight <*> request with correlation id <*> due to node 1 being disconnected (elapsed time since creation: <*> elapsed time since send: <*> throttle time: 0ms, request timeout: 2000ms)`: `rule: too few aligned samples: 10 aligned of 10 (need 20)`
- `kafka` `[NodeToControllerChannelManager id=1 name=heartbeat] Disconnecting from node 1 due to request timeout.`: `rule: too few aligned samples: 10 aligned of 10 (need 20)`
- `kafka` `[QuorumController id=1] <*> changing 51 partition(s)`: `rule: too few aligned samples: 8 aligned of 8 (need 20)`
- `kafka` `[QuorumController id=1] Fencing broker 1 at epoch 14 because its session has timed out.`: `rule: too few aligned samples: 4 aligned of 4 (need 20)`
- `kafka` `[QuorumController id=1] Periodic task <*> generated 0 records in <*> microseconds.`: `rule: too few aligned samples: 12 aligned of 12 (need 20)`
- `kafka` `[QuorumController id=1] Replayed BrokerRegistrationChangeRecord modifying the registration for broker 1: BrokerRegistrationChangeRecord(brokerId=1, brokerEpoch=14, <*> inControlledShutdown=0, logDirs=[], cordonedLogDirs=null)`: `rule: too few aligned samples: 8 aligned of 8 (need 20)`
- `kafka` `[QuorumController id=1] The request from broker 1 to unfence has been granted because it has caught up with the offset of its register broker record 14.`: `rule: too few aligned samples: 4 aligned of 4 (need 20)`
- `kafka` `[ReplicaFetcherManager on broker 1] Removed fetcher for partitions Set(__consumer_offsets-13, __consumer_offsets-46, __consumer_offsets-9, __consumer_offsets-42, __consumer_offsets-21, __consumer_offsets-17, __consumer_offsets-30, __consumer_offsets-26, __consumer_offsets-5, __consumer_offsets-38, __consumer_offsets-1, __consumer_offsets-34, __consumer_offsets-16, __consumer_offsets-45, __consumer_offsets-12, __consumer_offsets-41, __consumer_offsets-24, __consumer_offsets-20, __consumer_offsets-49, __consumer_offsets-0, __consumer_offsets-29, __consumer_offsets-25, __consumer_offsets-8, __consumer_offsets-37, __consumer_offsets-4, __consumer_offsets-33, __consumer_offsets-15, __consumer_offsets-48, __consumer_offsets-11, __consumer_offsets-44, __consumer_offsets-23, __consumer_offsets-19, __consumer_offsets-32, __consumer_offsets-28, __consumer_offsets-7, __consumer_offsets-40, __consumer_offsets-3, __consumer_offsets-36, __consumer_offsets-47, __consumer_offsets-14, __consumer_offsets-43, __consumer_offsets-10, __consumer_offsets-22, __consumer_offsets-18, __consumer_offsets-31, __consumer_offsets-27, __consumer_offsets-39, orders-0, __consumer_offsets-6, __consumer_offsets-35, __consumer_offsets-2)`: `rule: too few aligned samples: 8 aligned of 8 (need 20)`
- `kafka` `[UnifiedLog partition=__cluster_metadata-0, dir=/tmp/kafka-logs] Deleting segments due to log start offset 1562 breach: LogSegment(baseOffset=1464, size=1024, lastModifiedTime=1791161753649, largestRecordTimestamp=1791161753561),LogSegment(baseOffset=1485, size=985, lastModifiedTime=1791161769863, largestRecordTimestamp=1791161769060),LogSegment(baseOffset=1508, size=2924, lastModifiedTime=1791161795432, largestRecordTimestamp=1791161776553)`: `rule: too few aligned samples: 1 aligned of 1 (need 20)`
- `otelcol-contrib` `Error scraping metrics`: `rule: too few aligned samples: 7 aligned of 7 (need 20)`
- `otelcol-contrib` `OpenTelemetry internal telemetry error`: `rule: too few aligned samples: 1 aligned of 1 (need 20)`
- `recommendation` `Failed to export metrics to otel-collector:4317, error code: StatusCode.DEADLINE_EXCEEDED, error details: Deadline Exceeded`: `rule: too few aligned samples: 3 aligned of 3 (need 20)`
- `shipping` ` `: `no template (drain warm-up)`
- `shipping` `failed to resolve integer flag`: `rule: too few aligned samples: 4 aligned of 4 (need 20)`

Note: `3 queries the ruler executed are covered by its rules, which are read directly`
