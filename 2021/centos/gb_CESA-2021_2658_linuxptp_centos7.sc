if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.883360" );
	script_version( "2021-08-17T06:00:55+0000" );
	script_cve_id( "CVE-2021-3570" );
	script_tag( name: "cvss_base", value: "8.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:P/A:C" );
	script_tag( name: "last_modification", value: "2021-08-17 06:00:55 +0000 (Tue, 17 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-07-16 08:15:00 +0000 (Fri, 16 Jul 2021)" );
	script_tag( name: "creation_date", value: "2021-07-08 03:00:41 +0000 (Thu, 08 Jul 2021)" );
	script_name( "CentOS: Security Advisory for linuxptp (CESA-2021:2658)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "CentOS Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/centos", "ssh/login/rpms",  "ssh/login/release=CentOS7" );
	script_xref( name: "Advisory-ID", value: "CESA-2021:2658" );
	script_xref( name: "URL", value: "https://lists.centos.org/pipermail/centos-announce/2021-July/048341.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'linuxptp'
  package(s) announced via the CESA-2021:2658 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "The linuxptp packages provide Precision Time Protocol (PTP) implementation
for Linux according to IEEE standard 1588 for Linux. The dual design goals
are to provide a robust implementation of the standard and to use the most
relevant and modern Application Programming Interfaces (API) offered by the
Linux kernel.

Security Fix(es):

  * linuxptp: missing length check of forwarded messages (CVE-2021-3570)

For more details about the security issue(s), including the impact, a CVSS
score, acknowledgments, and other related information, refer to the CVE
page(s) listed in the References section." );
	script_tag( name: "affected", value: "'linuxptp' package(s) on CentOS 7." );
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
	if(!isnull( res = isrpmvuln( pkg: "linuxptp", rpm: "linuxptp~2.0~2.el7_9.1", rls: "CentOS7" ) )){
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

