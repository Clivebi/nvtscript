if(description){
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-1244-1/" );
	script_oid( "1.3.6.1.4.1.25623.1.0.840787" );
	script_version( "2020-08-18T09:42:52+0000" );
	script_tag( name: "last_modification", value: "2020-08-18 09:42:52 +0000 (Tue, 18 Aug 2020)" );
	script_tag( name: "creation_date", value: "2011-10-31 13:45:00 +0100 (Mon, 31 Oct 2011)" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_xref( name: "USN", value: "1244-1" );
	script_cve_id( "CVE-2010-3873", "CVE-2011-2183", "CVE-2011-2491", "CVE-2011-2494", "CVE-2011-2495", "CVE-2011-2517", "CVE-2011-2695", "CVE-2011-2905", "CVE-2011-2909", "CVE-2011-3363" );
	script_name( "Ubuntu Update for linux-ti-omap4 USN-1244-1" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU10\\.10" );
	script_tag( name: "summary", value: "Ubuntu Update for Linux kernel vulnerabilities USN-1244-1" );
	script_tag( name: "affected", value: "linux-ti-omap4 on Ubuntu 10.10" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "insight", value: "Dan Rosenberg discovered that the Linux kernel X.25 implementation
  incorrectly parsed facilities. A remote attacker could exploit this to
  crash the kernel, leading to a denial of service. (CVE-2010-3873)

  Andrea Righi discovered a race condition in the KSM memory merging support.
  If KSM was being used, a local attacker could exploit this to crash the
  system, leading to a denial of service. (CVE-2011-2183)

  Vasily Averin discovered that the NFS Lock Manager (NLM) incorrectly
  handled unlock requests. A local attacker could exploit this to cause a
  denial of service. (CVE-2011-2491)

  Vasiliy Kulikov discovered that taskstats did not enforce access
  restrictions. A local attacker could exploit this to read certain
  information, leading to a loss of privacy. (CVE-2011-2494)

  Vasiliy Kulikov discovered that /proc/PID/io did not enforce access
  restrictions. A local attacker could exploit this to read certain
  information, leading to a loss of privacy. (CVE-2011-2495)

  It was discovered that the wireless stack incorrectly verified SSID
  lengths. A local attacker could exploit this to cause a denial of service
  or gain root privileges. (CVE-2011-2517)

  It was discovered that the EXT4 filesystem contained multiple off-by-one
  flaws. A local attacker could exploit this to crash the system, leading to
  a denial of service. (CVE-2011-2695)

  Christian Ohm discovered that the perf command looks for configuration
  files in the current directory. If a privileged user were tricked into
  running perf in a directory containing a malicious configuration file, an
  attacker could run arbitrary commands and possibly gain privileges.
  (CVE-2011-2905)

  Vasiliy Kulikov discovered that the Comedi driver did not correctly clear
  memory. A local attacker could exploit this to read kernel stack memory,
  leading to a loss of privacy. (CVE-2011-2909)

  Yogesh Sharma discovered that CIFS did not correctly handle UNCs that had
  no prefixpaths. A local attacker with access to a CIFS partition could
  exploit this to crash the system, leading to a denial of service.
  (CVE-2011-3363)" );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
release = dpkg_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "UBUNTU10.10"){
	if(( res = isdpkgvuln( pkg: "linux-image-2.6.35-903-omap4", ver: "2.6.35-903.26", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

