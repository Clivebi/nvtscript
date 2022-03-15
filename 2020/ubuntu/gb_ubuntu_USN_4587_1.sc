if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.844666" );
	script_version( "2021-07-09T11:00:55+0000" );
	script_cve_id( "CVE-2014-6051", "CVE-2014-6052", "CVE-2014-6053", "CVE-2014-6054", "CVE-2014-6055", "CVE-2016-9941", "CVE-2016-9942", "CVE-2018-15127", "CVE-2018-20019", "CVE-2018-20020", "CVE-2018-20021", "CVE-2018-20022", "CVE-2018-20023", "CVE-2018-20024", "CVE-2018-20748", "CVE-2018-20749", "CVE-2018-20750", "CVE-2018-7225", "CVE-2019-15681" );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:C" );
	script_tag( name: "last_modification", value: "2021-07-09 11:00:55 +0000 (Fri, 09 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-10-23 13:15:00 +0000 (Fri, 23 Oct 2020)" );
	script_tag( name: "creation_date", value: "2020-10-22 03:00:29 +0000 (Thu, 22 Oct 2020)" );
	script_name( "Ubuntu: Security Advisory for italc (USN-4587-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU16\\.04 LTS" );
	script_xref( name: "USN", value: "4587-1" );
	script_xref( name: "URL", value: "https://lists.ubuntu.com/archives/ubuntu-security-announce/2020-October/005710.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'italc'
  package(s) announced via the USN-4587-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Nicolas Ruff discovered that iTALC had buffer overflows, divide-by-zero errors
and didn't check malloc return values. A remote attacker could use these issues
to cause a denial of service or possibly execute arbitrary code.
(CVE-2014-6051, CVE-2014-6052, CVE-2014-6053, CVE-2014-6054, CVE-2014-6055)

Josef Gajdusek discovered that iTALC had heap-based buffer overflow
vulnerabilities. A remote attacker could used these issues to cause a denial of
service or possibly execute arbitrary code. (CVE-2016-9941, CVE-2016-9942)

It was discovered that iTALC had an out-of-bounds write, multiple heap
out-of-bounds writes, an infinite loop, improper initializations, and null
pointer vulnerabilities. A remote attacker could used these issues to cause a
denial of service or possibly execute arbitrary code. (CVE-2018-15127,
CVE-2018-20019, CVE-2018-20020, CVE-2018-20021, CVE-2018-20022, CVE-2018-20023,
CVE-2018-20024, CVE-2018-20748, CVE-2018-20749, CVE-2018-20750, CVE-2018-7225,
CVE-2019-15681)" );
	script_tag( name: "affected", value: "'italc' package(s) on Ubuntu 16.04 LTS." );
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
if(release == "UBUNTU16.04 LTS"){
	if(!isnull( res = isdpkgvuln( pkg: "italc-client", ver: "1:2.0.2+dfsg1-4ubuntu0.1", rls: "UBUNTU16.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "italc-master", ver: "1:2.0.2+dfsg1-4ubuntu0.1", rls: "UBUNTU16.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "libitalccore", ver: "1:2.0.2+dfsg1-4ubuntu0.1", rls: "UBUNTU16.04 LTS" ) )){
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

