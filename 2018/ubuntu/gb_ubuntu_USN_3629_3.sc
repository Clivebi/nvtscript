if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.843517" );
	script_version( "2021-06-03T11:00:21+0000" );
	script_tag( name: "last_modification", value: "2021-06-03 11:00:21 +0000 (Thu, 03 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-05-08 09:25:32 +0200 (Tue, 08 May 2018)" );
	script_cve_id( "CVE-2018-2755", "CVE-2018-2758", "CVE-2018-2759", "CVE-2018-2761", "CVE-2018-2762", "CVE-2018-2766", "CVE-2018-2769", "CVE-2018-2771", "CVE-2018-2773", "CVE-2018-2779", "CVE-2018-2786", "CVE-2018-2816", "CVE-2018-2775", "CVE-2018-2776", "CVE-2018-2777", "CVE-2018-2778", "CVE-2018-2780", "CVE-2018-2781", "CVE-2018-2782", "CVE-2018-2784", "CVE-2018-2787", "CVE-2018-2810", "CVE-2018-2812", "CVE-2018-2813", "CVE-2018-2817", "CVE-2018-2818", "CVE-2018-2819", "CVE-2018-2839", "CVE-2018-2846" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:N/I:N/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-05-21 22:29:00 +0000 (Tue, 21 May 2019)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Ubuntu Update for mysql-5.7 USN-3629-3" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'mysql-5.7'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "USN-3629-1 fixed vulnerabilities in MySQL. This update provides the
corresponding updates for Ubuntu 18.04 LTS.

Original advisory details:

Multiple security issues were discovered in MySQL and this update includes
new upstream MySQL versions to fix these issues.
MySQL has been updated to 5.5.60 in Ubuntu 14.04 LTS. Ubuntu 16.04 LTS, and
Ubuntu 17.10 have been updated to MySQL 5.7.22.
In addition to security fixes, the updated packages contain bug fixes, new
features, and possibly incompatible changes.
Please see the references for more information." );
	script_xref( name: "URL", value: "http://dev.mysql.com/doc/relnotes/mysql/5.5/en/news-5-5-60.html" );
	script_xref( name: "URL", value: "http://dev.mysql.com/doc/relnotes/mysql/5.7/en/news-5-7-22.html" );
	script_xref( name: "URL", value: "http://www.oracle.com/technetwork/security-advisory/cpuapr2018-3678067.html" );
	script_tag( name: "affected", value: "mysql-5.7 on Ubuntu 18.04 LTS" );
	script_tag( name: "solution", value: "Please install the updated packages." );
	script_xref( name: "USN", value: "3629-3" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-3629-3/" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU18\\.04 LTS" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
release = dpkg_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "UBUNTU18.04 LTS"){
	if(( res = isdpkgvuln( pkg: "mysql-server-5.7", ver: "5.7.22-0ubuntu18.04.1", rls: "UBUNTU18.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

