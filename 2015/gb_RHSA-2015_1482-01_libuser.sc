if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.871415" );
	script_version( "$Revision: 12497 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-11-23 09:28:21 +0100 (Fri, 23 Nov 2018) $" );
	script_tag( name: "creation_date", value: "2015-08-03 15:07:58 +0530 (Mon, 03 Aug 2015)" );
	script_cve_id( "CVE-2015-3245", "CVE-2015-3246" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "RedHat Update for libuser RHSA-2015:1482-01" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'libuser'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The libuser library implements a standardized interface for manipulating
and administering user and group accounts. Sample applications that are
modeled after applications from the shadow password suite (shadow-utils)
are included in these packages.

Two flaws were found in the way the libuser library handled the /etc/passwd
file. A local attacker could use an application compiled against libuser
(for example, userhelper) to manipulate the /etc/passwd file, which could
result in a denial of service or possibly allow the attacker to escalate
their privileges to root. (CVE-2015-3245, CVE-2015-3246)

Red Hat would like to thank Qualys for reporting these issues.

All libuser users are advised to upgrade to these updated packages, which
contain a backported patch to correct this issue." );
	script_tag( name: "affected", value: "libuser on Red Hat Enterprise Linux Desktop (v. 6),
  Red Hat Enterprise Linux Server (v. 6),
  Red Hat Enterprise Linux Workstation (v. 6)" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "RHSA", value: "2015:1482-01" );
	script_xref( name: "URL", value: "https://www.redhat.com/archives/rhsa-announce/2015-July/msg00042.html" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "Red Hat Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/rhel", "ssh/login/rpms",  "ssh/login/release=RHENT_6" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-rpm.inc.sc");
release = rpm_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "RHENT_6"){
	if(( res = isrpmvuln( pkg: "libuser", rpm: "libuser~0.56.13~8.el6_7", rls: "RHENT_6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "libuser-debuginfo", rpm: "libuser-debuginfo~0.56.13~8.el6_7", rls: "RHENT_6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "libuser-python", rpm: "libuser-python~0.56.13~8.el6_7", rls: "RHENT_6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

