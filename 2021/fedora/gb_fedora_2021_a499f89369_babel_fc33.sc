if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.879558" );
	script_version( "2021-05-10T06:49:03+0000" );
	script_cve_id( "CVE-2021-20095" );
	script_tag( name: "cvss_base", value: "4.6" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-05-10 06:49:03 +0000 (Mon, 10 May 2021)" );
	script_tag( name: "creation_date", value: "2021-05-09 03:10:58 +0000 (Sun, 09 May 2021)" );
	script_name( "Fedora: Security Advisory for babel (FEDORA-2021-a499f89369)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC33" );
	script_xref( name: "Advisory-ID", value: "FEDORA-2021-a499f89369" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/MORYINYUSYI6XLC4UKPRGGFD2WMO7GSM" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'babel'
  package(s) announced via the FEDORA-2021-a499f89369 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Babel is composed of two major parts:

  * tools to build and work with gettext message catalogs

  * a Python interface to the CLDR (Common Locale Data Repository),
  providing access to various locale display names, localized number
  and date formatting, etc." );
	script_tag( name: "affected", value: "'babel' package(s) on Fedora 33." );
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
	if(!isnull( res = isrpmvuln( pkg: "babel", rpm: "babel~2.8.1~2.fc33", rls: "FC33" ) )){
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

