if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.878804" );
	script_version( "2021-08-23T06:00:57+0000" );
	script_cve_id( "CVE-2019-14690", "CVE-2019-14691", "CVE-2019-14692", "CVE-2019-14732", "CVE-2019-14733", "CVE-2019-14734", "CVE-2019-15151", "CVE-2018-17825" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-23 06:00:57 +0000 (Mon, 23 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-01-14 04:15:00 +0000 (Thu, 14 Jan 2021)" );
	script_tag( name: "creation_date", value: "2021-01-14 09:51:08 +0000 (Thu, 14 Jan 2021)" );
	script_name( "Fedora: Security Advisory for audacious-plugins (FEDORA-2021-64168929e4)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC33" );
	script_xref( name: "FEDORA", value: "2021-64168929e4" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/U3PW6PLDTPSQQRHKTU2FB72SUB4Q66NE" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'audacious-plugins'
  package(s) announced via the FEDORA-2021-64168929e4 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This package provides essential plugins for the Audacious audio player." );
	script_tag( name: "affected", value: "'audacious-plugins' package(s) on Fedora 33." );
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
	if(!isnull( res = isrpmvuln( pkg: "audacious-plugins", rpm: "audacious-plugins~4.0.5~3.fc33", rls: "FC33" ) )){
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

