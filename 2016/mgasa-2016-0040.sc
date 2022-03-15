if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.131202" );
	script_version( "2020-08-04T08:27:56+0000" );
	script_tag( name: "creation_date", value: "2016-02-02 07:44:19 +0200 (Tue, 02 Feb 2016)" );
	script_tag( name: "last_modification", value: "2020-08-04 08:27:56 +0000 (Tue, 04 Aug 2020)" );
	script_name( "Mageia Linux Local Check: mgasa-2016-0040" );
	script_tag( name: "insight", value: "A Cross-site scripting (XSS) vulnerability in the OCS discovery provider in ownCloud Server before 8.0.10 allows remote attackers to inject arbitrary web script or HTML via the URL resulting in a reflected Cross-Site-Scripting (CVE-2016-1498). ownCloud Server before 8.0.10 allows remote authenticated users to obtain sensitive information from a directory listing and possibly cause a denial of service (CPU consumption) via the force parameter to index.php/apps/files/ajax/scan.php (CVE-2015-1499). ownCloud Server before 8.0.10, when the file_versions application is enabled, does not properly check the return value of getOwner, which allows remote authenticated users to read the files with names starting with .v and belonging to a sharing user by leveraging an incoming share (CVE-2016-1500)." );
	script_tag( name: "solution", value: "Update the affected packages to the latest available version." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://advisories.mageia.org/MGASA-2016-0040.html" );
	script_cve_id( "CVE-2016-1498", "CVE-2016-1499", "CVE-2016-1500" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:N/A:C" );
	script_tag( name: "qod_type", value: "package" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/mageia_linux", "ssh/login/release",  "ssh/login/release=MAGEIA5" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "summary", value: "Mageia Linux Local Security Checks mgasa-2016-0040" );
	script_copyright( "Copyright (C) 2016 Eero Volotinen" );
	script_family( "Mageia Linux Local Security Checks" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-rpm.inc.sc");
release = rpm_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "MAGEIA5"){
	if(( res = isrpmvuln( pkg: "owncloud", rpm: "owncloud~8.0.10~1.mga5", rls: "MAGEIA5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

