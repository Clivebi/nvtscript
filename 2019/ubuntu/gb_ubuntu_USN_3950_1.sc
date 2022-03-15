if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.843981" );
	script_version( "2021-08-31T10:01:32+0000" );
	script_cve_id( "CVE-2019-9917" );
	script_tag( name: "cvss_base", value: "4.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-08-31 10:01:32 +0000 (Tue, 31 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-06-15 03:29:00 +0000 (Sat, 15 Jun 2019)" );
	script_tag( name: "creation_date", value: "2019-04-19 02:00:32 +0000 (Fri, 19 Apr 2019)" );
	script_name( "Ubuntu Update for znc USN-3950-1" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU18\\.10" );
	script_xref( name: "USN", value: "3950-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-3950-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'znc'
  package(s) announced via the USN-3950-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "It was discovered that ZNC incorrectly handled certain invalid encodings.
An authenticated remote user could use this issue to cause ZNC to crash,
resulting in a denial of service, or possibly execute arbitrary code." );
	script_tag( name: "affected", value: "'znc' package(s) on Ubuntu 18.10." );
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
if(release == "UBUNTU18.10"){
	if(!isnull( res = isdpkgvuln( pkg: "znc", ver: "1.7.1-2ubuntu0.1", rls: "UBUNTU18.10" ) )){
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

