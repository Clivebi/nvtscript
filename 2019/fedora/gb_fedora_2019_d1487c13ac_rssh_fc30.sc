if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.876972" );
	script_version( "2021-09-01T12:01:34+0000" );
	script_cve_id( "CVE-2019-3463", "CVE-2019-3464", "CVE-2019-1000018" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-01 12:01:34 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-05-28 19:57:00 +0000 (Fri, 28 May 2021)" );
	script_tag( name: "creation_date", value: "2019-11-10 03:24:10 +0000 (Sun, 10 Nov 2019)" );
	script_name( "Fedora Update for rssh FEDORA-2019-d1487c13ac" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC30" );
	script_xref( name: "FEDORA", value: "2019-d1487c13ac" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/T42YYNWJZG422GATWAHAEK4A24OKY557" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'rssh'
  package(s) announced via the FEDORA-2019-d1487c13ac advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "rssh is a restricted shell for use with OpenSSH, allowing only scp
and/or sftp. For example, if you have a server which you only want
to allow users to copy files off of via scp, without providing shell
access, you can use rssh to do that. It is an alternative to scponly." );
	script_tag( name: "affected", value: "'rssh' package(s) on Fedora 30." );
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
if(release == "FC30"){
	if(!isnull( res = isrpmvuln( pkg: "rssh", rpm: "rssh~2.3.4~15.fc30", rls: "FC30" ) )){
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

