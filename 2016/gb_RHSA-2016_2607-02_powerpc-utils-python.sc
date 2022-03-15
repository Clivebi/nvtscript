if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.871697" );
	script_version( "$Revision: 12497 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-11-23 09:28:21 +0100 (Fri, 23 Nov 2018) $" );
	script_tag( name: "creation_date", value: "2016-11-04 05:42:08 +0100 (Fri, 04 Nov 2016)" );
	script_cve_id( "CVE-2014-8165" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "RedHat Update for powerpc-utils-python RHSA-2016:2607-02" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'powerpc-utils-python'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The powerpc-utils-python packages provide
Python-based utilities for maintaining and servicing PowerPC systems.

Security Fix(es):

  * It was found that the amsvis command of the powerpc-utils-python package
did not verify unpickled data before processing it. This could allow an
attacker who can connect to an amsvis server process (or cause an amsvis
client process to connect to them) to execute arbitrary code as the user
running the amsvis process. (CVE-2014-8165)

This issue was discovered by Dhiru Kholia of Red Hat Product Security.

Additional Changes:

For detailed information on changes in this release, see the Red Hat
Enterprise Linux 7.3 Release Notes linked from the References section." );
	script_tag( name: "affected", value: "powerpc-utils-python on Red Hat Enterprise Linux Server (v. 7)" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "RHSA", value: "2016:2607-02" );
	script_xref( name: "URL", value: "https://www.redhat.com/archives/rhsa-announce/2016-November/msg00043.html" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Red Hat Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/rhel", "ssh/login/rpms",  "ssh/login/release=RHENT_7" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-rpm.inc.sc");
release = rpm_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "RHENT_7"){
	if(( res = isrpmvuln( pkg: "powerpc-utils-python", rpm: "powerpc-utils-python~1.2.1~9.el7", rls: "RHENT_7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

