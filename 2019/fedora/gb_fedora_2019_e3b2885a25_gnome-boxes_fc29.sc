if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.875622" );
	script_version( "2021-09-01T10:01:36+0000" );
	script_cve_id( "CVE-2018-1000852", "CVE-2018-8786" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-01 10:01:36 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-09-29 02:09:00 +0000 (Tue, 29 Sep 2020)" );
	script_tag( name: "creation_date", value: "2019-05-07 02:12:26 +0000 (Tue, 07 May 2019)" );
	script_name( "Fedora Update for gnome-boxes FEDORA-2019-e3b2885a25" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC29" );
	script_xref( name: "FEDORA", value: "2019-e3b2885a25" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/XRKSZJA3RC4TAZHPLLI7L2GYP6CKWWUC" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'gnome-boxes'
  package(s) announced via the FEDORA-2019-e3b2885a25 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "gnome-boxes lets you easily create, setup, access, and use:

  * remote machines

  * remote virtual machines

  * local virtual machines

  * When technology permits, set up access for applications on
    local virtual machines" );
	script_tag( name: "affected", value: "'gnome-boxes' package(s) on Fedora 29." );
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
	if(!isnull( res = isrpmvuln( pkg: "gnome-boxes", rpm: "gnome-boxes~3.30.3~2.fc29", rls: "FC29" ) )){
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

