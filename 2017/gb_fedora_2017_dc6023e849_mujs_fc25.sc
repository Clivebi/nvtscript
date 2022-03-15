if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.872402" );
	script_version( "2021-09-13T14:16:31+0000" );
	script_tag( name: "last_modification", value: "2021-09-13 14:16:31 +0000 (Mon, 13 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-02-23 05:08:37 +0100 (Thu, 23 Feb 2017)" );
	script_cve_id( "CVE-2016-10132", "CVE-2016-10133", "CVE-2016-10141", "CVE-2017-5627", "CVE-2017-5628" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-03-27 16:54:00 +0000 (Mon, 27 Mar 2017)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Fedora Update for mujs FEDORA-2017-dc6023e849" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'mujs'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "mujs on Fedora 25" );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_xref( name: "FEDORA", value: "2017-dc6023e849" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/T3U5APFS3FEBOPXUJIFWBNU55PYR7ZBF" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC25" );
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
if(release == "FC25"){
	if(!isnull( res = isrpmvuln( pkg: "mujs", rpm: "mujs~0~8.20170124git4006739.fc25", rls: "FC25" ) )){
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

