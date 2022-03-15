if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.844912" );
	script_version( "2021-08-19T14:00:55+0000" );
	script_cve_id( "CVE-2021-28963" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-08-19 14:00:55 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-03-26 14:13:00 +0000 (Fri, 26 Mar 2021)" );
	script_tag( name: "creation_date", value: "2021-04-23 03:00:35 +0000 (Fri, 23 Apr 2021)" );
	script_name( "Ubuntu: Security Advisory for shibboleth-sp (USN-4925-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU20\\.04 LTS" );
	script_xref( name: "Advisory-ID", value: "USN-4925-1" );
	script_xref( name: "URL", value: "https://lists.ubuntu.com/archives/ubuntu-security-announce/2021-April/005987.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'shibboleth-sp'
  package(s) announced via the USN-4925-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Toni Huttunen and Fraktal Oy discovered that the Shibboleth Service
provider allowed content injection due to allowing attacker-controlled
parameters in error or other status pages. An attacker could use this to
inject malicious content." );
	script_tag( name: "affected", value: "'shibboleth-sp' package(s) on Ubuntu 20.04 LTS." );
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
if(release == "UBUNTU20.04 LTS"){
	if(!isnull( res = isdpkgvuln( pkg: "libapache2-mod-shib", ver: "3.0.4+dfsg1-1ubuntu0.1", rls: "UBUNTU20.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "libshibsp-plugins", ver: "3.0.4+dfsg1-1ubuntu0.1", rls: "UBUNTU20.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "libshibsp8", ver: "3.0.4+dfsg1-1ubuntu0.1", rls: "UBUNTU20.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "shibboleth-sp-common", ver: "3.0.4+dfsg1-1ubuntu0.1", rls: "UBUNTU20.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "shibboleth-sp-utils", ver: "3.0.4+dfsg1-1ubuntu0.1", rls: "UBUNTU20.04 LTS" ) )){
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

