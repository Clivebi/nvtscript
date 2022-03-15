if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.876669" );
	script_version( "2021-09-01T11:01:35+0000" );
	script_cve_id( "CVE-2019-1010301", "CVE-2019-1010302", "CVE-2018-16554", "CVE-2016-3822" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-01 11:01:35 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-12-31 20:15:00 +0000 (Tue, 31 Dec 2019)" );
	script_tag( name: "creation_date", value: "2019-08-14 02:34:41 +0000 (Wed, 14 Aug 2019)" );
	script_name( "Fedora Update for jhead FEDORA-2019-441c2fb0d1" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC29" );
	script_xref( name: "FEDORA", value: "2019-441c2fb0d1" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/YTGUHTJTQ6EKEPDXFSKZKVLUJC4UAPBQ" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'jhead'
  package(s) announced via the FEDORA-2019-441c2fb0d1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Jhead displays and manipulates the non-image portions of EXIF formatted
JPEG images, such as the images produced by most digital cameras." );
	script_tag( name: "affected", value: "'jhead' package(s) on Fedora 29." );
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
	if(!isnull( res = isrpmvuln( pkg: "jhead", rpm: "jhead~3.03~4.fc29", rls: "FC29" ) )){
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

