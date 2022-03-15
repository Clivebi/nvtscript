if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.876767" );
	script_version( "2021-09-01T08:01:24+0000" );
	script_cve_id( "CVE-2019-5736" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-09-01 08:01:24 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-07-01 20:15:00 +0000 (Thu, 01 Jul 2021)" );
	script_tag( name: "creation_date", value: "2019-09-07 02:24:06 +0000 (Sat, 07 Sep 2019)" );
	script_name( "Fedora Update for lxcfs FEDORA-2019-c1dac1b3b8" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC29" );
	script_xref( name: "FEDORA", value: "2019-c1dac1b3b8" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/744HVBCKN5JUL3CHQ24OQUR76WXCYQ2W" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'lxcfs'
  package(s) announced via the FEDORA-2019-c1dac1b3b8 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "LXCFS is a simple userspace filesystem designed to work around some
current limitations of the Linux kernel.

Specifically, it&#39, s providing two main things

  - A set of files which can be bind-mounted over their /proc originals
  to provide CGroup-aware values.

  - A cgroupfs-like tree which is container aware.

The code is pretty simple, written in C using libfuse.

The main driver for this work was the need to run systemd based
containers as a regular unprivileged user while still allowing systemd
inside the container to interact with cgroups.

Now with the introduction of the cgroup namespace in the Linux kernel,
that part is no longer necessary on recent kernels and focus is now on
making containers feel more like a real independent system through the
proc masking feature." );
	script_tag( name: "affected", value: "'lxcfs' package(s) on Fedora 29." );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-rpm.inc.sc");
release = rpm_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
report = "";
if(release == "FC29"){
	if(!isnull( res = isrpmvuln( pkg: "lxcfs", rpm: "lxcfs~3.0.4~1.fc29", rls: "FC29" ) )){
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

