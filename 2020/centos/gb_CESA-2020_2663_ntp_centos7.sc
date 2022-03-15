if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.883258" );
	script_version( "2021-07-05T11:01:33+0000" );
	script_cve_id( "CVE-2020-11868", "CVE-2020-13817" );
	script_tag( name: "cvss_base", value: "5.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-07-05 11:01:33 +0000 (Mon, 05 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-07-27 02:15:00 +0000 (Mon, 27 Jul 2020)" );
	script_tag( name: "creation_date", value: "2020-06-24 03:01:19 +0000 (Wed, 24 Jun 2020)" );
	script_name( "CentOS: Security Advisory for ntp (CESA-2020:2663)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "CentOS Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/centos", "ssh/login/rpms",  "ssh/login/release=CentOS7" );
	script_xref( name: "CESA", value: "2020:2663" );
	script_xref( name: "URL", value: "https://lists.centos.org/pipermail/centos-announce/2020-June/035768.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'ntp'
  package(s) announced via the CESA-2020:2663 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "The Network Time Protocol (NTP) is used to synchronize a computer's time
with another referenced time source. These packages include the ntpd
service which continuously adjusts system time and utilities used to query
and configure the ntpd service.

Security Fix(es):

  * ntp: ntpd using highly predictable transmit timestamps could result in
time change or DoS (CVE-2020-13817)

  * ntp: DoS on client ntpd using server mode packet (CVE-2020-11868)

For more details about the security issue(s), including the impact, a CVSS
score, acknowledgments, and other related information, refer to the CVE
page(s) listed in the References section." );
	script_tag( name: "affected", value: "'ntp' package(s) on CentOS 7." );
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
if(release == "CentOS7"){
	if(!isnull( res = isrpmvuln( pkg: "ntp", rpm: "ntp~4.2.6p5~29.el7.centos.2", rls: "CentOS7" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ntpdate", rpm: "ntpdate~4.2.6p5~29.el7.centos.2", rls: "CentOS7" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ntp-doc", rpm: "ntp-doc~4.2.6p5~29.el7.centos.2", rls: "CentOS7" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ntp-perl", rpm: "ntp-perl~4.2.6p5~29.el7.centos.2", rls: "CentOS7" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "sntp", rpm: "sntp~4.2.6p5~29.el7.centos.2", rls: "CentOS7" ) )){
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

