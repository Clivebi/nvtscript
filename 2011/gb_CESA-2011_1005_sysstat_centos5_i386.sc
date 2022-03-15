if(description){
	script_xref( name: "URL", value: "http://lists.centos.org/pipermail/centos-announce/2011-September/018036.html" );
	script_oid( "1.3.6.1.4.1.25623.1.0.880987" );
	script_version( "$Revision: 14222 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-15 13:50:48 +0100 (Fri, 15 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2011-09-23 16:39:49 +0200 (Fri, 23 Sep 2011)" );
	script_tag( name: "cvss_base", value: "4.4" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:M/Au:N/C:P/I:P/A:P" );
	script_xref( name: "CESA", value: "2011:1005" );
	script_cve_id( "CVE-2007-3852" );
	script_name( "CentOS Update for sysstat CESA-2011:1005 centos5 i386" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'sysstat'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2011 Greenbone Networks GmbH" );
	script_family( "CentOS Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/centos", "ssh/login/rpms",  "ssh/login/release=CentOS5" );
	script_tag( name: "affected", value: "sysstat on CentOS 5" );
	script_tag( name: "insight", value: "The sysstat package contains a set of utilities which enable system
  monitoring of disks, network, and other I/O activity.

  It was found that the sysstat initscript created a temporary file in an
  insecure way. A local attacker could use this flaw to create arbitrary
  files via a symbolic link attack. (CVE-2007-3852)

  This update fixes the following bugs:

  * On systems under heavy load, the sadc utility would sometimes output the
  following error message if a write() call was unable to write all of the
  requested input:

  'Cannot write data to system activity file: Success.'

  In this updated package, the sadc utility tries to write the remaining
  input, resolving this issue. (BZ#454617)

  * On the Itanium architecture, the 'sar -I' command provided incorrect
  information about the interrupt statistics of the system. With this update,
  the 'sar -I' command has been disabled for this architecture, preventing
  this bug. (BZ#468340)

  * Previously, the 'iostat -n' command used invalid data to create
  statistics for read and write operations. With this update, the data source
  for these statistics has been fixed, and the iostat utility now returns
  correct information. (BZ#484439)

  * The 'sar -d' command used to output invalid data about block devices.
  With this update, the sar utility recognizes disk registration and disk
  overflow statistics properly, and only correct and relevant data is now
  displayed. (BZ#517490)

  * Previously, the sar utility set the maximum number of days to be logged
  in one month too high. Consequently, data from a month was appended to
  data from the preceding month. With this update, the maximum number of days
  has been set to 25, and data from a month now correctly replaces data from
  the preceding month. (BZ#578929)

  * In previous versions of the iostat utility, the number of NFS mount
  points was hard-coded. Consequently, various issues occurred while iostat
  was running and NFS mount points were mounted or unmounted. Certain values
  in iostat reports overflowed and some mount points were not reported at
  all. With this update, iostat properly recognizes when an NFS mount point
  mounts or unmounts, fixing these issues. (BZ#675058, BZ#706095, BZ#694767)

  * When a device name was longer than 13 characters, the iostat utility
  printed a redundant new line character, making its output less readable.
  This bug has been fixed and now, no extra characters are printed if a long
  device name occurs in iostat output. (BZ#604637)

  * Previously, if kernel inte ...

  Description truncated, please see the referenced URL(s) for more information." );
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
	if(( res = isrpmvuln( pkg: "sysstat", rpm: "sysstat~7.0.2~11.el5", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
