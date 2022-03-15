if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.874383" );
	script_version( "2021-06-10T02:00:20+0000" );
	script_tag( name: "last_modification", value: "2021-06-10 02:00:20 +0000 (Thu, 10 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-04-25 08:51:34 +0200 (Wed, 25 Apr 2018)" );
	script_cve_id( "CVE-2018-7600", "CVE-2017-6926", "CVE-2017-6927", "CVE-2017-6930", "CVE-2017-6931", "CVE-2017-6923", "CVE-2017-6924", "CVE-2017-6925", "CVE-2017-6920", "CVE-2017-6921", "CVE-2017-6922", "CVE-2017-6928", "CVE-2017-6929", "CVE-2017-6932" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-03-01 18:04:00 +0000 (Fri, 01 Mar 2019)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Fedora Update for drupal8 FEDORA-2018-922cc2fbaa" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'drupal8'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "drupal8 on Fedora 26" );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_xref( name: "FEDORA", value: "2018-922cc2fbaa" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/S4QXGSUTNGLGN67JM5KBVWO26ICKTRXL" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC26" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-rpm.inc.sc");
release = rpm_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "FC26"){
	if(( res = isrpmvuln( pkg: "drupal8", rpm: "drupal8~8.3.9~1.fc26", rls: "FC26" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

