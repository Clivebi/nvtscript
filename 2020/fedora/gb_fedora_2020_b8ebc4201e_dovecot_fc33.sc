if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.878367" );
	script_version( "2021-07-21T11:00:56+0000" );
	script_cve_id( "CVE-2020-12100", "CVE-2020-12673", "CVE-2020-10967", "CVE-2020-12674" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-07-21 11:00:56 +0000 (Wed, 21 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-01-06 23:15:00 +0000 (Wed, 06 Jan 2021)" );
	script_tag( name: "creation_date", value: "2020-09-26 03:13:34 +0000 (Sat, 26 Sep 2020)" );
	script_name( "Fedora: Security Advisory for dovecot (FEDORA-2020-b8ebc4201e)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC33" );
	script_xref( name: "FEDORA", value: "2020-b8ebc4201e" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/XKKAL3OMG76ZZ7CIEMQP2K6KCTD2RAKE" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'dovecot'
  package(s) announced via the FEDORA-2020-b8ebc4201e advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Dovecot is an IMAP server for Linux/UNIX-like systems, written with security
primarily in mind.  It also contains a small POP3 server.  It supports mail
in either of maildir or mbox formats.

The SQL drivers and authentication plug-ins are in their subpackages." );
	script_tag( name: "affected", value: "'dovecot' package(s) on Fedora 33." );
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
if(release == "FC33"){
	if(!isnull( res = isrpmvuln( pkg: "dovecot", rpm: "dovecot~2.3.11.3~5.fc33", rls: "FC33" ) )){
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

