if(description){
	script_xref( name: "URL", value: "http://lists.centos.org/pipermail/centos-announce/2009-December/016366.html" );
	script_oid( "1.3.6.1.4.1.25623.1.0.880801" );
	script_version( "$Revision: 14222 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-15 13:50:48 +0100 (Fri, 15 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2011-08-09 08:20:34 +0200 (Tue, 09 Aug 2011)" );
	script_tag( name: "cvss_base", value: "4.4" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:M/Au:N/C:P/I:P/A:P" );
	script_xref( name: "CESA", value: "2009:1619" );
	script_cve_id( "CVE-2009-3894" );
	script_name( "CentOS Update for dstat CESA-2009:1619 centos5 i386" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'dstat'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2011 Greenbone Networks GmbH" );
	script_family( "CentOS Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/centos", "ssh/login/rpms",  "ssh/login/release=CentOS5" );
	script_tag( name: "affected", value: "dstat on CentOS 5" );
	script_tag( name: "insight", value: "Dstat is a versatile replacement for the vmstat, iostat, and netstat tools.
  Dstat can be used for performance tuning tests, benchmarks, and
  troubleshooting.

  Robert Buchholz of the Gentoo Security Team reported a flaw in the Python
  module search path used in dstat. If a local attacker could trick a
  local user into running dstat from a directory containing a Python script
  that is named like an importable module, they could execute arbitrary code
  with the privileges of the user running dstat. (CVE-2009-3894)

  All dstat users should upgrade to this updated package, which contains a
  backported patch to correct this issue." );
	script_tag( name: "solution", value: "Please install the updated packages." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
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
	if(( res = isrpmvuln( pkg: "dstat", rpm: "dstat~0.6.6~3.el5_4.1", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

