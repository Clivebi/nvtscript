if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.879511" );
	script_version( "2021-05-10T06:49:03+0000" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-05-10 06:49:03 +0000 (Mon, 10 May 2021)" );
	script_tag( name: "creation_date", value: "2021-05-03 03:09:42 +0000 (Mon, 03 May 2021)" );
	script_name( "Fedora: Security Advisory for babel (FEDORA-2021-3fb798ea36)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC34" );
	script_xref( name: "Advisory-ID", value: "FEDORA-2021-3fb798ea36" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/J6N66MDKHESXGMHWX4YKNW7DWXMQVL3F" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'babel'
  package(s) announced via the FEDORA-2021-3fb798ea36 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Babel is composed of two major parts:

  * tools to build and work with gettext message catalogs

  * a Python interface to the CLDR (Common Locale Data Repository),
  providing access to various locale display names, localized number
  and date formatting, etc." );
	script_tag( name: "affected", value: "'babel' package(s) on Fedora 34." );
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
if(release == "FC34"){
	if(!isnull( res = isrpmvuln( pkg: "babel", rpm: "babel~2.9.1~1.fc34", rls: "FC34" ) )){
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

