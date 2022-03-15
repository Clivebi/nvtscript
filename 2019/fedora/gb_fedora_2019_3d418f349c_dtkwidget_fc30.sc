if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.876618" );
	script_version( "2021-09-02T10:01:39+0000" );
	script_cve_id( "CVE-2019-13228", "CVE-2019-13229", "CVE-2019-13227", "CVE-2019-13226" );
	script_tag( name: "cvss_base", value: "6.9" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-09-02 10:01:39 +0000 (Thu, 02 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-07-28 03:15:00 +0000 (Sun, 28 Jul 2019)" );
	script_tag( name: "creation_date", value: "2019-07-29 02:16:26 +0000 (Mon, 29 Jul 2019)" );
	script_name( "Fedora Update for dtkwidget FEDORA-2019-3d418f349c" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC30" );
	script_xref( name: "FEDORA", value: "2019-3d418f349c" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/7OEZR6KOON76ZZHIBPK4UVUOMTQUFU3M" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'dtkwidget'
  package(s) announced via the FEDORA-2019-3d418f349c advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "DtkWidget is Deepin graphical user interface for deepin desktop development." );
	script_tag( name: "affected", value: "'dtkwidget' package(s) on Fedora 30." );
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
if(release == "FC30"){
	if(!isnull( res = isrpmvuln( pkg: "dtkwidget", rpm: "dtkwidget~2.0.16.1~1.fc30", rls: "FC30" ) )){
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
