if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.882247" );
	script_version( "$Revision: 14058 $" );
	script_cve_id( "CVE-2013-7424" );
	script_tag( name: "cvss_base", value: "5.1" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:H/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-08 14:25:52 +0100 (Fri, 08 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2015-08-18 06:49:41 +0200 (Tue, 18 Aug 2015)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "CentOS Update for glibc CESA-2015:1627 centos5" );
	script_tag( name: "summary", value: "Check the version of glibc" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The glibc packages provide the standard C libraries (libc), POSIX thread
libraries (libpthread), standard math libraries (libm), and the Name Server
Caching Daemon (nscd) used by multiple programs on the system.
Without these libraries, the Linux system cannot function correctly.

An invalid free flaw was found in glibc's getaddrinfo() function when used
with the AI_IDN flag. A remote attacker able to make an application call
this function could use this flaw to execute arbitrary code with the
permissions of the user running the application. Note that this flaw only
affected applications using glibc compiled with libidn support.
(CVE-2013-7424)

All glibc users are advised to upgrade to these updated packages, which
contain a backported patch to correct this issue." );
	script_tag( name: "affected", value: "glibc on CentOS 5" );
	script_tag( name: "solution", value: "Please install the updated packages." );
	script_xref( name: "CESA", value: "2015:1627" );
	script_xref( name: "URL", value: "http://lists.centos.org/pipermail/centos-announce/2015-August/021336.html" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "CentOS Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/centos", "ssh/login/rpms",  "ssh/login/release=CentOS5" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-rpm.inc.sc");
release = rpm_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "CentOS5"){
	if(( res = isrpmvuln( pkg: "glibc", rpm: "glibc~2.5~123.el5_11.3", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "glibc-common", rpm: "glibc-common~2.5~123.el5_11.3", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "glibc-devel", rpm: "glibc-devel~2.5~123.el5_11.3", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "glibc-headers", rpm: "glibc-headers~2.5~123.el5_11.3", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "glibc-utils", rpm: "glibc-utils~2.5~123.el5_11.3", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "nscd", rpm: "nscd~2.5~123.el5_11.3", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

