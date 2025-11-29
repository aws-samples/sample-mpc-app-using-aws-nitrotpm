import React, { useEffect, useRef, useState } from 'react';
import * as d3 from 'd3';
import { Box, Typography, Card, CardContent, IconButton } from '@mui/material';
import { Close as CloseIcon } from '@mui/icons-material';

const FlowDiagram = () => {
  const svgRef = useRef();
  const [selectedNode, setSelectedNode] = useState(null);
  const [cardPosition, setCardPosition] = useState({ x: 0, y: 0 });

  const nodeDetails = {
    partyA: { title: "Party A - Model Owner", description: "Encrypts and uploads model weights using AWS KMS. Verifies EC2 Instance attestation before sealing data to specific PCR measurements." },
    S3: { title: "Amazon S3 Storage", description: "Secure cloud storage for encrypted model files and data keys. Provides durable storage and publishing mechanism." },
    EC2: { title: "EC2 Instance Attestation", description: "Isolated compute environment with hardware-backed attestation. Provides secure model decryption and execution with PCR measurements." },
    partyB: { title: "Party B - Model Consumer", description: "Verifies attestation documents and loads models securely. Ensures trusted execution environment before model usage." },
    chat: { title: "Chat Interface (Ollama)", description: "LLM inference endpoint providing chat capabilities. Runs securely within the EC2 Instance with verified model integrity." }
  };

  useEffect(() => {
    const svg = d3.select(svgRef.current);
    svg.selectAll("*").remove();

    const width = 800;
    const height = 400;
    
    svg.attr("width", width).attr("height", height);

    // Define nodes with mutable positions
    let nodes = [
      { id: "partyA", x: 100, y: 100, label: "Party A\nModel Owner", color: "#1976D2" },
      { id: "S3", x: 300, y: 100, label: "S3\nEncrypted Model", color: "#FF9800" },
      { id: "EC2", x: 500, y: 200, label: "EC2 Instance", color: "#F57C00" },
      { id: "partyB", x: 700, y: 100, label: "Party B\nModel Consumer", color: "#388E3C" },
      { id: "chat", x: 700, y: 300, label: "Chat Interface\nOllama", color: "#2196F3" }
    ];

    // Define links
    const links = [
      { source: "partyA", target: "s3", label: "Encrypt & Upload", direction: "→" },
      { source: "S3", target: "EC2", label: "Download & Decrypt", direction: "↘" },
      { source: "EC2", target: "partyB", label: "Attestation Verify", direction: "↗" },
      { source: "partyB", target: "chat", label: "Load Model", direction: "↓" },
      { source: "chat", target: "EC2", label: "Inference Requests", direction: "↰" }
    ];

    // Create arrow marker
    svg.append("defs").append("marker")
      .attr("id", "arrowhead")
      .attr("viewBox", "0 -5 10 10")
      .attr("refX", 10)
      .attr("refY", 0)
      .attr("markerWidth", 8)
      .attr("markerHeight", 8)
      .attr("orient", "auto")
      .append("path")
      .attr("d", "M0,-5L10,0L0,5")
      .attr("fill", "#333");

    // Create links group
    const linkGroup = svg.append("g").attr("class", "links");
    
    const updateLinks = () => {
      linkGroup.selectAll("*").remove();
      
      links.forEach(link => {
        const sourceNode = nodes.find(n => n.id === link.source);
        const targetNode = nodes.find(n => n.id === link.target);
        
        // Calculate control point for curve
        const midX = (sourceNode.x + targetNode.x) / 2;
        const midY = (sourceNode.y + targetNode.y) / 2;
        const offset = link.source === "chat" ? -100 : 50;
        const controlX = midX + (sourceNode.y > targetNode.y ? -offset : offset);
        const controlY = midY - 30;
        
        // Curved path
        linkGroup.append("path")
          .attr("d", `M ${sourceNode.x} ${sourceNode.y} Q ${controlX} ${controlY} ${targetNode.x} ${targetNode.y}`)
          .attr("stroke", "#333")
          .attr("stroke-width", 3)
          .attr("fill", "none")
          .attr("marker-end", "url(#arrowhead)");

        // Labels
        const labelX = (sourceNode.x + targetNode.x) / 2;
        const labelY = (sourceNode.y + targetNode.y) / 2 - 40;
        
        linkGroup.append("text")
          .attr("x", labelX)
          .attr("y", labelY - 15)
          .attr("text-anchor", "middle")
          .attr("font-size", "16px")
          .attr("font-weight", "bold")
          .attr("fill", "#2196F3")
          .text(link.direction);
        
        linkGroup.append("text")
          .attr("x", labelX)
          .attr("y", labelY)
          .attr("text-anchor", "middle")
          .attr("font-size", "12px")
          .attr("font-weight", "bold")
          .attr("fill", "#333")
          .text(link.label);
      });
    };
    
    updateLinks();



    // Create nodes with drag and click behavior
    const nodeGroup = svg.append("g").attr("class", "nodes");
    
    const drag = d3.drag()
      .on("drag", function(event, d) {
        d.x = event.x;
        d.y = event.y;
        d3.select(this).attr("transform", `translate(${d.x}, ${d.y})`);
        updateLinks();
      });
    
    nodes.forEach(node => {
      const g = nodeGroup.append("g")
        .datum(node)
        .attr("transform", `translate(${node.x}, ${node.y})`)
        .style("cursor", "pointer")
        .call(drag)
        .on("click", function(event, d) {
          event.stopPropagation();
          setSelectedNode(d.id);
          const svgRect = svgRef.current.getBoundingClientRect();
          setCardPosition({ 
            x: event.clientX - svgRect.left, 
            y: event.clientY - svgRect.top 
          });
        });
      
      // Node rectangle
      g.append("rect")
        .attr("x", -50)
        .attr("y", -25)
        .attr("width", 100)
        .attr("height", 50)
        .attr("rx", 8)
        .attr("fill", node.color)
        .attr("stroke", "white")
        .attr("stroke-width", 2)
        .attr("stroke-dasharray", "0")
        .style("transition", "all 0.2s")
        .on("mouseover", function() {
          d3.select(this).attr("stroke-width", 4);
        })
        .on("mouseout", function() {
          d3.select(this).attr("stroke-width", 2);
        });
      
      // Node label
      const lines = node.label.split('\n');
      lines.forEach((line, i) => {
        g.append("text")
          .attr("text-anchor", "middle")
          .attr("dy", (i - lines.length/2 + 0.5) * 14)
          .attr("font-size", "11px")
          .attr("font-weight", "bold")
          .attr("fill", "white")
          .text(line)
          .style("pointer-events", "none");
      });
    });
    
    // Click on canvas to dismiss card
    svg.on("click", () => {
      setSelectedNode(null);
    });

  }, []);

  return (
    <Box sx={{ textAlign: 'center', p: 2, position: 'relative' }}>
      <Typography variant="h6" gutterBottom sx={{ color: '#4A4A4A', mb: 3 }}>
        Multi-Party Collaboration Flow (Drag nodes, click for details)
      </Typography>
      <svg ref={svgRef}></svg>
      
      {selectedNode && (
        <Card 
          sx={{ 
            position: 'absolute',
            left: Math.max(10, Math.min(cardPosition.x - 150, 500)),
            top: Math.max(10, cardPosition.y + 50),
            width: 300,
            zIndex: 1000,
            boxShadow: 3,
            backgroundColor: 'white'
          }}
        >
          <CardContent>
            <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
              <Box>
                <Typography variant="h6" gutterBottom>
                  {nodeDetails[selectedNode]?.title}
                </Typography>
                <Typography variant="body2" color="text.secondary">
                  {nodeDetails[selectedNode]?.description}
                </Typography>
              </Box>
              <IconButton 
                size="small" 
                onClick={() => setSelectedNode(null)}
                sx={{ ml: 1 }}
              >
                <CloseIcon fontSize="small" />
              </IconButton>
            </Box>
          </CardContent>
        </Card>
      )}
    </Box>
  );
};

export default FlowDiagram;