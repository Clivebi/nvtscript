if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.876573" );
	script_version( "2021-09-01T08:01:24+0000" );
	script_cve_id( "CVE-2019-10691", "CVE-2019-7524", "CVE-2019-3814", "CVE-2019-11494", "CVE-2019-11499" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-09-01 08:01:24 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-06-14 03:29:00 +0000 (Fri, 14 Jun 2019)" );
	script_tag( name: "creation_date", value: "2019-07-13 02:14:32 +0000 (Sat, 13 Jul 2019)" );
	script_name( "Fedora Update for dovecot FEDORA-2019-1b61a528dd" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC29" );
	script_xref( name: "FEDORA", value: "2019-1b61a528dd" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/QHFZ5OWRIZGIWZJ5PTNVWWZNLLNH4XYS" );
	script_tag( name: "summary", value: "The remote host is missing an update for the
  'dovecot' package(s) announced via the FEDORA-2019-1b61a528dd advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is
  present on the target host." );
	script_tag( name: "insight", value: "Dovecot is an IMAP server for Linux/UNIX-like
  systems, written with security primarily in mind.  It also contains a small
  POP3 server.  It supports mail in either of maildir or mbox formats.

The SQL drivers and authentication plug-ins are in their subpackages." );
	script_tag( name: "affected", value: "'dovecot' package(s) on Fedora 29." );
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
if(release == "FC29"){
	if(!isnull( res = isrpmvuln( pkg: "dovecot", rpm: "dovecot~2.3.6~3.fc29", rls: "FC29" ) )){
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

