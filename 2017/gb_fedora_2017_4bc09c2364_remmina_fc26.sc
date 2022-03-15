if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.873198" );
	script_version( "2021-09-17T08:01:48+0000" );
	script_tag( name: "last_modification", value: "2021-09-17 08:01:48 +0000 (Fri, 17 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-08-04 12:46:57 +0530 (Fri, 04 Aug 2017)" );
	script_cve_id( "CVE-2017-2836", "CVE-2017-2837", "CVE-2017-2838", "CVE-2017-2839", "CVE-2017-2835", "CVE-2017-2834" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-05-25 15:20:00 +0000 (Fri, 25 May 2018)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Fedora Update for remmina FEDORA-2017-4bc09c2364" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'remmina'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "remmina on Fedora 26" );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_xref( name: "FEDORA", value: "2017-4bc09c2364" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/YO2U577L6Q7PHBNVQ3ZL2VARNKYZBSYL" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
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
	if(( res = isrpmvuln( pkg: "remmina", rpm: "remmina~1.2.0~0.39.20170724git0387ee0.fc26", rls: "FC26" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

