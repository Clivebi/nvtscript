if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.875529" );
	script_version( "2021-08-31T14:01:23+0000" );
	script_cve_id( "CVE-2018-18409" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-08-31 14:01:23 +0000 (Tue, 31 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-05-13 15:46:00 +0000 (Mon, 13 May 2019)" );
	script_tag( name: "creation_date", value: "2019-03-28 13:55:36 +0000 (Thu, 28 Mar 2019)" );
	script_name( "Fedora Update for tcpflow FEDORA-2019-8cdd669aca" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC28" );
	script_xref( name: "FEDORA", value: "2019-8cdd669aca" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/K6MP4YMCJX4ITOBFX427UMOA6E7ZLJDE" );
	script_tag( name: "summary", value: "The remote host is missing an update for the
  'tcpflow' package(s) announced via the FEDORA-2019-8cdd669aca advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is
  present on the target host." );
	script_tag( name: "insight", value: "tcpflow is a program that captures data
  transmitted as part of TCP connections (flows), and stores the data in a way
  that is convenient for protocol analysis or debugging. A program like &#39
  tcpdump&#39  shows a summary of packets seen on the wire, but usually doesn&#39
  t store the data that&#39 s actually being transmitted. In contrast, tcpflow
  reconstructs the actual data streams and stores each flow in a separate file
  for later analysis." );
	script_tag( name: "affected", value: "'tcpflow' package(s) on Fedora 28." );
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
if(release == "FC28"){
	if(!isnull( res = isrpmvuln( pkg: "tcpflow", rpm: "tcpflow~1.5.0~4.fc28", rls: "FC28" ) )){
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
