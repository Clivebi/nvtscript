if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.876889" );
	script_version( "2021-09-01T11:01:35+0000" );
	script_cve_id( "CVE-2019-9853", "CVE-2019-9854", "CVE-2019-9855", "CVE-2019-9850", "CVE-2019-9851", "CVE-2019-9852", "CVE-2019-9848", "CVE-2019-9849" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-01 11:01:35 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-09-25 12:15:00 +0000 (Wed, 25 Sep 2019)" );
	script_tag( name: "creation_date", value: "2019-10-10 02:22:55 +0000 (Thu, 10 Oct 2019)" );
	script_name( "Fedora Update for libreoffice FEDORA-2019-4b0cc75996" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC29" );
	script_xref( name: "FEDORA", value: "2019-4b0cc75996" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/KQGBRSD73KTDZ2MPAOL7FBWO3SQVYE5B" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'libreoffice'
  package(s) announced via the FEDORA-2019-4b0cc75996 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "LibreOffice is an Open Source, community-developed, office productivity suite.
It includes the key desktop applications, such as a word processor,
spreadsheet, presentation manager, formula editor and drawing program, with a
user interface and feature set similar to other office suites.  Sophisticated
and flexible, LibreOffice also works transparently with a variety of file
formats, including Microsoft Office File Formats." );
	script_tag( name: "affected", value: "'libreoffice' package(s) on Fedora 29." );
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
	if(!isnull( res = isrpmvuln( pkg: "libreoffice", rpm: "libreoffice~6.1.6.3~5.fc29", rls: "FC29" ) )){
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

