if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.874281" );
	script_version( "2021-06-14T02:00:24+0000" );
	script_tag( name: "last_modification", value: "2021-06-14 02:00:24 +0000 (Mon, 14 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-03-26 08:34:00 +0200 (Mon, 26 Mar 2018)" );
	script_cve_id( "CVE-2018-7711", "CVE-2018-7644", "CVE-2018-6519" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-03-29 15:24:00 +0000 (Thu, 29 Mar 2018)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Fedora Update for php-simplesamlphp-saml2 FEDORA-2018-f4ab4d96f9" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'php-simplesamlphp-saml2'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "php-simplesamlphp-saml2 on Fedora 26" );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_xref( name: "FEDORA", value: "2018-f4ab4d96f9" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/H4W3DGTKU6LRNHENVRWWJETHIE5N3LHT" );
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
	if(( res = isrpmvuln( pkg: "php-simplesamlphp-saml2", rpm: "php-simplesamlphp-saml2~2.3.8~1.fc26", rls: "FC26" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
