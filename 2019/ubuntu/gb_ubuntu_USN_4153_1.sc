if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.844199" );
	script_version( "2021-08-31T11:01:29+0000" );
	script_cve_id( "CVE-2019-17134" );
	script_tag( name: "cvss_base", value: "6.4" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-08-31 11:01:29 +0000 (Tue, 31 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-11-06 19:15:00 +0000 (Wed, 06 Nov 2019)" );
	script_tag( name: "creation_date", value: "2019-10-11 02:00:38 +0000 (Fri, 11 Oct 2019)" );
	script_name( "Ubuntu Update for octavia USN-4153-1" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU19\\.04" );
	script_xref( name: "USN", value: "4153-1" );
	script_xref( name: "URL", value: "https://lists.ubuntu.com/archives/ubuntu-security-announce/2019-October/005146.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'octavia'
  package(s) announced via the USN-4153-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Daniel Preussker discovered that Octavia incorrectly handled client
certificate checking. A remote attacker on the management network could
possibly use this issue to perform configuration changes and obtain
sensitive information." );
	script_tag( name: "affected", value: "'octavia' package(s) on Ubuntu 19.04." );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
release = dpkg_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
report = "";
if(release == "UBUNTU19.04"){
	if(!isnull( res = isdpkgvuln( pkg: "amphora-agent", ver: "4.0.0-0ubuntu1.2", rls: "UBUNTU19.04" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "octavia-common", ver: "4.0.0-0ubuntu1.2", rls: "UBUNTU19.04" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "python3-octavia", ver: "4.0.0-0ubuntu1.2", rls: "UBUNTU19.04" ) )){
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

