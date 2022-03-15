if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.875550" );
	script_version( "2021-09-01T09:01:32+0000" );
	script_cve_id( "CVE-2018-1000852", "CVE-2018-8786" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-01 09:01:32 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-09-29 02:09:00 +0000 (Tue, 29 Sep 2020)" );
	script_tag( name: "creation_date", value: "2019-04-05 02:08:27 +0000 (Fri, 05 Apr 2019)" );
	script_name( "Fedora Update for remmina FEDORA-2019-b2d986c3e9" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC28" );
	script_xref( name: "FEDORA", value: "2019-b2d986c3e9" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/YVJKO2DR5EY4C4QZOP7SNNBEW2JW6FHX" );
	script_tag( name: "summary", value: "The remote host is missing an update
  for the 'remmina' package(s) announced via the FEDORA-2019-b2d986c3e9
  advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present
  on the target host." );
	script_tag( name: "insight", value: "Remmina is a remote desktop client written
  in GTK+, aiming to be useful for system administrators and travelers, who need
  to work with lots of remote computers in front of either large monitors or
  tiny net-books.

Remmina supports multiple network protocols in an integrated and consistent
user interface. Currently RDP, VNC, XDMCP and SSH are supported.

Please don&#39, t forget to install the plugins for the protocols you want to use." );
	script_tag( name: "affected", value: "'remmina' package(s) on Fedora 28." );
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
if(release == "FC28"){
	if(!isnull( res = isrpmvuln( pkg: "remmina", rpm: "remmina~1.3.3~1.fc28", rls: "FC28" ) )){
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
