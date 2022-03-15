if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.852784" );
	script_version( "2021-09-07T10:01:34+0000" );
	script_cve_id( "CVE-2019-14241" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-09-07 10:01:34 +0000 (Tue, 07 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2019-11-24 03:00:40 +0000 (Sun, 24 Nov 2019)" );
	script_name( "openSUSE: Security Advisory for haproxy (openSUSE-SU-2019:2555-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.0" );
	script_xref( name: "openSUSE-SU", value: "2019:2555-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/opensuse-security-announce/2019-11/msg00060.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'haproxy'
  package(s) announced via the openSUSE-SU-2019:2555-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for haproxy to version 2.0.5+git0.d905f49a fixes the following
  issues:

  Security issue fixed:

  - CVE-2019-14241: Fixed a cookie memory corruption problem. (bsc#1142529)

  The update to 2.0.5 brings lots of features and bugfixes:

  - new internal native HTTP representation called HTX, was already in 1.9
  and is now enabled by default in 2.0

  - end-to-end HTTP/2 support including trailers and continuation frames, as
  needed for gRPC, HTTP/2 may also be upgraded from HTTP/1.1 using the H2
  preface,

  - server connection pooling and more advanced reuse, with ALPN protocol
  negotiation (already in 1.9)

  - layer 7 retries, allowing to use 0-RTT and TCP Fast Open to the servers
  as well as on the frontend

  - much more scalable multi-threading, which is even enabled by default on
  platforms where it was successfully tested, by default, as many threads
  are started as the number of CPUs haproxy is allowed to run on. This
  removes a lot of configuration burden in VMs and containers

  - automatic maxconn setting for the process and the frontends, directly
  based on the number of available FDs (easier configuration in containers
  and with systemd)

  - logging to stdout for use in containers and systemd (already in 1.9).
  Logs can now provide micro-second resolution for some events

  - peers now support SSL, declaration of multiple stick-tables directly in
  the peers section, and synchronization of server names, not just IDs

  - In master-worker mode, the master process now exposes its own CLI and
  can communicate with all other processes (including the stopping ones),
  even allowing to connect to their CLI and check their state. It is also
  possible to start some sidecar programs and monitor them from the
  master, and the master can automatically kill old processes that
  survived too many reloads

  - the incoming connections are load-balanced between all threads depending
  on their load to minimize the processing time and maximize the capacity
  (already in 1.9)

  - the SPOE connection load-balancing was significantly improved in order
  to reduce high percentiles of SPOA response time (already in 1.9)

  - the 'random' load balancing algorithm and a power-of-two-choices variant
  were introduced

  - statistics improvements with per-thread counters for certain things, and
  a prometheus exporter for all our statistics,

  - lots of debugging help, it's easier to produce a core dump, there are
  new commands on the CLI to control various things, there is a watchdog
  to fail cleanly when a thread deadlock or a spinning task are detected,
  so overall it shoul ...

  Description truncated. Please see the references for more information." );
	script_tag( name: "affected", value: "'haproxy' package(s) on openSUSE Leap 15.0." );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-rpm.inc.sc");
release = rpm_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
report = "";
if(release == "openSUSELeap15.0"){
	if(!isnull( res = isrpmvuln( pkg: "haproxy", rpm: "haproxy~2.0.5+git0.d905f49a~lp150.2.13.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "haproxy-debuginfo", rpm: "haproxy-debuginfo~2.0.5+git0.d905f49a~lp150.2.13.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "haproxy-debugsource", rpm: "haproxy-debugsource~2.0.5+git0.d905f49a~lp150.2.13.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if( report != "" ){
		security_message( data: report );
	}
	else {
		if(__pkg_match){
			exit( 99 );
		}
	}
	exit( 0 );
}
exit( 0 );

