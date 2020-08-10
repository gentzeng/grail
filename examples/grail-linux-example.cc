/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */

#include "ns3/grail-module.h"
#include "ns3/traffic-control-module.h"

#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/applications-module.h"
#include "ns3/csma-module.h"
#include "ns3/internet-module.h"
#include "ns3/error-model.h"

#include <pwd.h>
#include <unistd.h>
#include <sys/types.h>

#include "ns3/int64x64-128.h"

#include <iostream>
#include <functional>

using namespace ns3;

int
main (int argc, char *argv[])
{
  LogComponentEnable("GrailApplication", LOG_LEVEL_ERROR);
  //LogComponentEnable("GrailApplication", LOG_LEVEL_LOGIC);

  uint32_t rngRun = 0;
  bool pcap = true;
  bool enablePreloading = true;
  DataRate rate = DataRate("1Mbps");

  CommandLine cmd;
  cmd.AddValue("rngRun", "run-# of the PRNG", rngRun);
  cmd.AddValue("rate", "bitrate of link", rate);
  cmd.AddValue("pcap", "enable pcap", pcap);
  cmd.AddValue("enablePreloading", "enable LD-preloading helper technique", enablePreloading);
  cmd.Parse (argc, argv);

  RngSeedManager::SetRun(rngRun);

  NodeContainer nodes;
  nodes.Create(2 /* num nodes */);

  Ptr<RateErrorModel> rem = CreateObject<RateErrorModel> ();
  Ptr<UniformRandomVariable> uv = CreateObject<UniformRandomVariable> ();
  rem->SetRandomVariable (uv);
  rem->SetRate (1.0/rate.GetBitRate());

  CsmaHelper csma;
  csma.SetDeviceAttribute ("ReceiveErrorModel", PointerValue(rem));
  csma.SetChannelAttribute ("Delay", StringValue ("1ms"));
  csma.SetChannelAttribute ("DataRate", DataRateValue(rate));
  NetDeviceContainer devices0 = csma.Install(nodes);

  InternetStackHelper stack;
  stack.Install (nodes);
  Ipv4AddressHelper address;
  address.SetBase ("10.0.0.0", "255.255.255.0");
  Ipv4InterfaceContainer interfaces0 = address.Assign(devices0);
  Ipv4GlobalRoutingHelper::PopulateRoutingTables ();

  ApplicationContainer serverApps; // only used for baseline
  {
    Ptr<GrailApplication> app = CreateObject<GrailApplication>();
    app->Setup({"/var/linux-grail/linux",
				"root=/dev/root","rootfstype=hostfs",
				"rootflags=/var/rootfs-grail",
				"rw", "mem=2G", "eth0=daemon,10:00:00:00:00:01,,",
				"init=/bin/grail", "uml_dir=/var/tmp/"});
    app->SetAttribute("PrintStdout", BooleanValue(true));
    app->SetAttribute("SyscallProcessingTime", TimeValue(NanoSeconds(100)));
    app->SetAttribute("EnablePreloading", BooleanValue(enablePreloading));
    app->SetAttribute("MayQuit", BooleanValue(true));
    app->SetStartTime( Seconds(0.0) );
    app->SetStopTime( Seconds(20.0) );
    nodes.Get (0)->AddApplication(app);
  }

  if(pcap) {
    csma.EnablePcapAll ("kairos");
  }

  Simulator::Stop( Seconds (50) );
  Simulator::Run ();
  Simulator::Destroy ();

  return 0;
}
